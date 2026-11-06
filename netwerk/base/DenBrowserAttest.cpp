/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// DenBrowser per-request ECIES attestation header injector — v2 protocol.
//
// Adds three HTTP headers to every outbound HTTP/HTTPS request:
//
//   X-DenBrowser-Ts:    current Unix timestamp (seconds, decimal string).
//   X-DenBrowser-Nonce: base64( 16 random bytes ), fresh per request.
//   X-DenBrowser-Token: base64( ephem_pub(65) || IV(12) || AES-128-GCM-ct ).
//
// The ciphertext decrypts to a canonical plaintext that binds the request
// to its method, host, path, and body hash:
//
//   "denbrowser-attest:v2\n<nonce_b64>\n<ts>\n<host>\n<method>\n<path>\n<sha256_hex>"
//
// Replaying the captured (Ts, Nonce, Token) triple in a different request
// now fails because:
//   - The proxy rejects any nonce it has already seen (replay cache).
//   - The plaintext binds the request semantics, so a captured token is only
//     valid for the exact (method, host, path, body) it was issued for.
//
// A deployment may front several partner applications, each behind its own
// attestation proxy with its own keypair.  The proxy table below maps the
// domains a partner's proxy serves to that proxy's public key, and a request
// is attested with the key of the entry claiming its host.  A host claimed by
// no entry is sent out untouched.
//
// The proxy private keys never appear in this file or the browser binary;
// only the proxies' public keys are embedded.

#include "DenBrowserAttest.h"

#include "cert.h"
#include "certt.h"
#include "keyhi.h"
#include "mozilla/Base64.h"
#include "mozilla/Logging.h"
#include "mozilla/StaticMutex.h"
#include "mozilla/UniquePtr.h"
#include "nsComponentManagerUtils.h"
#include "nsHttp.h"
#include "nsHttpRequestHead.h"
#include "nsICloneableInputStream.h"
#include "nsICryptoHash.h"
#include "nsIInputStream.h"
#include "nsIURI.h"
#include "nsStreamUtils.h"
#include "nsString.h"
#include "pk11pub.h"
#include "prtime.h"
#include "ScopedNSSTypes.h"
#include "secasn1.h"
#include "secitem.h"

#include <cstring>
#include <iterator>  // std::size

namespace denbrowser {

using mozilla::UniqueCERTSubjectPublicKeyInfo;
using mozilla::UniquePK11SlotInfo;
using mozilla::UniquePK11SymKey;
using mozilla::UniqueSECKEYPrivateKey;
using mozilla::UniqueSECKEYPublicKey;

static mozilla::LazyLogModule sLog("DenBrowserAttest");

// ── Proxy table ───────────────────────────────────────────────────────────────
//
// One entry per attestation proxy.  A deployment fronting several partner
// applications runs one proxy per partner, each with its own keypair, so the
// browser has to pick the right key for the host it is about to talk to
// rather than assuming a single global proxy.
//
// Each entry pairs the domains a proxy serves with:
//   - mAttestKey — SubjectPublicKeyInfo DER of that proxy's EC P-256
//     attestation public key.  Its private half stays on the proxy and never
//     belongs in this file.  A valid P-256 SPKI blob is 91 bytes, first byte
//     0x30 (ASN.1 SEQUENCE).
//   - mSpkiPin — sha256 of that proxy's TLS server-cert SubjectPublicKeyInfo,
//     used by patch 012's VerifyProxyPin().  Null when the deployment has not
//     pinned this proxy.
//
// The block between the DEN: PROXY_TABLE sentinels is GENERATED: build.sh
// (Step 2.5) rewrites it from the "proxies" array in config/site-config.json.
// Do not hand-edit it — edit the JSON and rebuild.  The default below is the
// unconfigured, empty table, in which every function here is a silent no-op
// and requests go out unmodified, so dev builds work before any proxy exists.
//
//   config/site-config.json:
//     "proxies": [
//       { "name":       "partner-a",
//         "domains":    ["app.partner-a.example.com"],
//         "attest_key": "partner-a-public.der",
//         "tls_cert":   "partner-a-tls.crt" }
//     ]
//
//   scripts/gen-attest-key.sh --name partner-a
//   scripts/gen-proxy-tls.sh  --name partner-a --host app.partner-a.example.com
//
// There is deliberately no catch-all/wildcard domain: a host nobody claims is
// not proxied, so attesting it would leak attestation headers to third-party
// servers that have no key to verify them.

struct DenProxyEntry {
  // Label from site-config.json, used in log messages.  A null name
  // terminates the table.
  const char* mName;
  // Hostnames this proxy fronts, null-terminated.  Matched exactly or as a
  // parent domain ("partner-a.com" also claims "app.partner-a.com").
  const char* const* mDomains;
  // Attestation public key (SPKI DER) and its length.
  const uint8_t* mAttestKey;
  uint32_t mAttestKeyLen;
  // 32-byte sha256(SPKI) TLS pin, or null when this proxy is not pinned.
  // Read only by patch 012; harmlessly unused when that patch is skipped.
  const uint8_t* mSpkiPin;
};

// clang-format off
// ── DEN: PROXY_TABLE ──
static const DenProxyEntry kDenProxies[] = {
  {nullptr, nullptr, nullptr, 0, nullptr},
};
// ── DEN END: PROXY_TABLE ──
// clang-format on

// Table slots including the terminator.  The key cache below is sized from
// this, so a generated table of any length needs no other change here.
static constexpr size_t kDenProxySlots = std::size(kDenProxies);

// ── P-256 curve params for ephemeral keygen ───────────────────────────────────
// DER encoding of OID prime256v1 (1.2.840.10045.3.1.7):
//   06 08 2a 86 48 ce 3d 03 01 07
static const uint8_t kP256OidDer[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                      0xce, 0x3d, 0x03, 0x01, 0x07};

// ── Host → proxy lookup ───────────────────────────────────────────────────────

// Exact host match, or aHost is a subdomain of aPat.  Same rule the site
// filter (patch 014) applies, so one deployment's domain lists behave
// identically wherever they appear.
static bool ProxyHostMatch(const nsACString& aHost, const char* aPat) {
  nsDependentCString pat(aPat);
  if (aHost.Equals(pat)) return true;
  // Subdomain match: host must end with "." + pattern.
  if (aHost.Length() > pat.Length() + 1) {
    return aHost.CharAt(aHost.Length() - pat.Length() - 1) == '.' &&
           Substring(aHost, aHost.Length() - pat.Length()).Equals(pat);
  }
  return false;
}

// Index into kDenProxies of the proxy fronting aHost, or -1 when no configured
// proxy claims it.  First match wins, so when one entry's domain is a parent of
// another's, list the more specific entry first (build.sh warns about this).
static int32_t FindProxyForHost(const nsACString& aHost) {
  for (int32_t i = 0; kDenProxies[i].mName; ++i) {
    for (const char* const* d = kDenProxies[i].mDomains; d && *d; ++d) {
      if (ProxyHostMatch(aHost, *d)) return i;
    }
  }
  return -1;
}

// ── Cached proxy public keys ──────────────────────────────────────────────────

static mozilla::StaticMutex sKeyMutex;
// Imported keys, parallel to kDenProxies.  Process-lifetime; never freed.
static SECKEYPublicKey* sProxyPubKeys[kDenProxySlots];
static bool sKeysLoaded = false;

// Import every configured proxy's public key, once per process.  Called before
// the host lookup so an unconfigured build says so on its first request, when
// no lookup could ever match.  An entry whose DER fails to import is skipped
// rather than fatal: one bad key in the table must not take down attestation
// for the other partners' proxies.
static void EnsureProxyKeysLoaded() {
  mozilla::StaticMutexAutoLock lock(sKeyMutex);
  if (sKeysLoaded) return;
  sKeysLoaded = true;

  if (!kDenProxies[0].mName) {
    MOZ_LOG(sLog, mozilla::LogLevel::Warning,
            ("DenBrowserAttest: no proxies configured — request attestation "
             "is DISABLED.  Add a \"proxies\" entry to "
             "config/site-config.json (see scripts/gen-attest-key.sh) and "
             "rebuild."));
    return;
  }

  for (size_t i = 0; kDenProxies[i].mName; ++i) {
    const DenProxyEntry& entry = kDenProxies[i];

    // Valid P-256 SPKI DER starts with 0x30 (ASN.1 SEQUENCE).
    if (!entry.mAttestKey || entry.mAttestKeyLen == 0 ||
        entry.mAttestKey[0] != 0x30) {
      MOZ_LOG(sLog, mozilla::LogLevel::Error,
              ("DenBrowserAttest: proxy \"%s\" has no valid attestation key — "
               "its traffic will NOT be attested.",
               entry.mName));
      continue;
    }

    SECItem spkiItem = {siBuffer, const_cast<uint8_t*>(entry.mAttestKey),
                        entry.mAttestKeyLen};

    UniqueCERTSubjectPublicKeyInfo spki(
        SECKEY_DecodeDERSubjectPublicKeyInfo(&spkiItem));
    if (!spki) {
      MOZ_LOG(sLog, mozilla::LogLevel::Error,
              ("DenBrowserAttest: SECKEY_DecodeDERSubjectPublicKeyInfo failed "
               "for proxy \"%s\" (bad DER bytes?).",
               entry.mName));
      continue;
    }

    SECKEYPublicKey* key = SECKEY_ExtractPublicKey(spki.get());
    if (!key) {
      MOZ_LOG(sLog, mozilla::LogLevel::Error,
              ("DenBrowserAttest: SECKEY_ExtractPublicKey failed for proxy "
               "\"%s\".",
               entry.mName));
      continue;
    }

    sProxyPubKeys[i] = key;
  }
}

// The public key of proxy aIndex, or nullptr when that entry has no usable one.
static SECKEYPublicKey* GetProxyPublicKey(int32_t aIndex) {
  EnsureProxyKeysLoaded();
  if (aIndex < 0 || static_cast<size_t>(aIndex) >= kDenProxySlots) {
    return nullptr;
  }
  mozilla::StaticMutexAutoLock lock(sKeyMutex);
  return sProxyPubKeys[aIndex];
}

// ── Body hashing ──────────────────────────────────────────────────────────────
// Returns lowercase hex SHA-256 of the request body.  Clones the upload stream
// so the original is left untouched and the actual upload sends the same bytes
// the proxy will hash on its side.  A null stream correctly hashes as empty;
// clone, read, or hash failures are returned to the caller rather than silently
// producing a digest for a partial body.

static nsresult HashBody(nsIInputStream* aUploadStream, nsACString& aHexHash) {
  nsCOMPtr<nsICryptoHash> hasher =
      do_CreateInstance("@mozilla.org/security/hash;1");
  if (!hasher) return NS_ERROR_FAILURE;
  nsresult rv = hasher->Init(nsICryptoHash::SHA256);
  NS_ENSURE_SUCCESS(rv, rv);

  if (aUploadStream) {
    nsCOMPtr<nsIInputStream> clone;
    rv = NS_CloneInputStream(aUploadStream, getter_AddRefs(clone));
    NS_ENSURE_SUCCESS(rv, rv);

    char buf[4096];
    while (true) {
      uint32_t read = 0;
      rv = clone->Read(buf, sizeof(buf), &read);
      NS_ENSURE_SUCCESS(rv, rv);
      if (read == 0) break;

      rv = hasher->Update(reinterpret_cast<uint8_t*>(buf), read);
      NS_ENSURE_SUCCESS(rv, rv);
    }
  }

  nsAutoCString rawDigest;
  rv = hasher->Finish(false /* aASCII=false → raw bytes */, rawDigest);
  NS_ENSURE_SUCCESS(rv, rv);

  static const char kHexDigits[] = "0123456789abcdef";
  aHexHash.Truncate();
  aHexHash.SetCapacity(rawDigest.Length() * 2);
  for (uint32_t i = 0; i < rawDigest.Length(); ++i) {
    uint8_t b = static_cast<uint8_t>(rawDigest.CharAt(i));
    aHexHash.Append(kHexDigits[b >> 4]);
    aHexHash.Append(kHexDigits[b & 0xf]);
  }
  return NS_OK;
}

// ── Body binding policy ─────────────────────────────────────────────────────
// Uploads larger than this are sent "unbound" (no body hash) so the proxy can
// stream them straight through instead of buffering + hashing.  This must stay
// at or below the proxy's BOUND_BODY_MAX so a *bound* upload is never buffered
// past the proxy's cap and rejected with 413.  That cap is pingora's request
// retry-buffer limit (BODY_BUF_LIMIT, 64 KiB): the proxy verifies a bound body
// in full before contacting the upstream and then relies on that retry buffer
// to replay it, and the buffer silently truncates past its capacity.  Origin,
// replay, timestamp, and method/host/path binding still apply to unbound
// uploads; only per-body integrity is dropped for them.
static const uint64_t kMaxBoundBodyBytes = 64 * 1024;  // 64 KiB (proxy retry-buffer cap)

// Decide whether to skip the body hash (emit the "unbound" sentinel) for this
// upload.  We skip when the body is too large to hash cheaply up front, or when
// the stream cannot be cloned (we cannot hash it without consuming the bytes the
// actual upload still needs to send).
static bool ShouldSkipBodyHash(nsIInputStream* aUploadStream,
                               uint64_t aUploadLength) {
  if (!aUploadStream) {
    return false;  // No body: sha256("") is correct and trivial to bind.
  }

  // mReqContentLength is populated when Firefox normalizes the upload stream,
  // and describes the whole upload.  Available() only reports bytes that can
  // be read without blocking and is not a stream-length API.
  if (aUploadLength > kMaxBoundBodyBytes) {
    return true;
  }

  // Not cloneable → hashing would consume the upload bytes.  Stream unbound.
  nsCOMPtr<nsICloneableInputStream> cloneable = do_QueryInterface(aUploadStream);
  if (!cloneable || !cloneable->GetCloneable()) {
    return true;
  }
  return false;
}

// ── Public API ────────────────────────────────────────────────────────────────

nsresult AddAttestHeaders(mozilla::net::nsHttpRequestHead& aHead, nsIURI* aURI,
                          nsIInputStream* aUploadStream,
                          uint64_t aUploadLength) {
  MOZ_ASSERT(aURI);

  // Import the configured keys (once per process) before anything else, so an
  // unconfigured build logs that attestation is off even though the host
  // lookup below can never match.
  EnsureProxyKeysLoaded();

  // ── 1. Host ──────────────────────────────────────────────────────────────
  // Non-HTTP resources (about:, data:, blob:, …) have no host; skip them.
  // GetAsciiHost is already lowercase punycode, matching the domain form
  // build.sh writes into the proxy table.
  nsAutoCString host;
  if (NS_FAILED(aURI->GetAsciiHost(host)) || host.IsEmpty()) {
    return NS_OK;
  }

  // ── 2. Proxy selection ───────────────────────────────────────────────────
  // Attest only to hosts a configured proxy fronts, with that proxy's own key.
  // Anything else is left untouched: a third-party server holds no private key
  // to verify these headers, so sending them there would only leak them.
  int32_t proxyIndex = FindProxyForHost(host);
  if (proxyIndex < 0) {
    MOZ_LOG(sLog, mozilla::LogLevel::Debug,
            ("DenBrowserAttest: no proxy configured for host=%s — sending "
             "unattested.",
             host.get()));
    return NS_OK;
  }

  SECKEYPublicKey* proxyPubKey = GetProxyPublicKey(proxyIndex);
  if (!proxyPubKey) {
    return NS_OK;  // Unusable key for this proxy — already logged.
  }

  // ── 3. Timestamp ─────────────────────────────────────────────────────────
  int64_t ts = static_cast<int64_t>(PR_Now() / PR_USEC_PER_SEC);
  nsAutoCString tsStr;
  tsStr.AppendInt(ts);

  // ── 4. Method (already uppercase in nsHttpRequestHead) ───────────────────
  nsAutoCString method;
  aHead.Method(method);

  // ── 5. Path + query (strip fragment; servers never see it) ───────────────
  nsAutoCString path;
  if (NS_FAILED(aURI->GetPathQueryRef(path))) {
    return NS_OK;
  }
  int32_t fragIdx = path.FindChar('#');
  if (fragIdx >= 0) path.Truncate(fragIdx);
  if (path.IsEmpty()) path.AssignLiteral("/");

  // ── 6. Random 16-byte nonce + base64 ─────────────────────────────────────
  uint8_t nonceBytes[16];
  if (PK11_GenerateRandom(nonceBytes, sizeof(nonceBytes)) != SECSuccess) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: PK11_GenerateRandom (nonce) failed."));
    return NS_OK;
  }
  nsAutoCString nonceB64;
  nsresult nsrv = mozilla::Base64Encode(
      reinterpret_cast<const char*>(nonceBytes), sizeof(nonceBytes), nonceB64);
  if (NS_FAILED(nsrv)) return NS_OK;

  // ── 7. Body binding (sha256 hex, or the "unbound" sentinel) ──────────────
  nsAutoCString bodyHex;
  if (ShouldSkipBodyHash(aUploadStream, aUploadLength)) {
    // Large / unhashable upload: emit the authenticated "unbound" marker and
    // let the proxy stream the body without buffering.  (See the proxy's
    // request_body_filter and attest.rs BodyBinding::Unbound.)
    bodyHex.AssignLiteral("unbound");
  } else {
    nsresult rv = HashBody(aUploadStream, bodyHex);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  // ── 8. Canonical plaintext ───────────────────────────────────────────────
  nsAutoCString plaintext;
  plaintext.AppendLiteral("denbrowser-attest:v2\n");
  plaintext.Append(nonceB64);
  plaintext.Append('\n');
  plaintext.Append(tsStr);
  plaintext.Append('\n');
  plaintext.Append(host);
  plaintext.Append('\n');
  plaintext.Append(method);
  plaintext.Append('\n');
  plaintext.Append(path);
  plaintext.Append('\n');
  plaintext.Append(bodyHex);

  // ── 9. Ephemeral EC P-256 keypair ────────────────────────────────────────
  UniquePK11SlotInfo slot(PK11_GetInternalSlot());
  if (!slot) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: PK11_GetInternalSlot failed."));
    return NS_OK;
  }

  SECItem curveParams = {siBuffer, const_cast<uint8_t*>(kP256OidDer),
                         static_cast<unsigned int>(sizeof(kP256OidDer))};
  SECKEYPublicKey* ephemPubRaw = nullptr;
  UniqueSECKEYPrivateKey ephemPriv(
      PK11_GenerateKeyPair(slot.get(), CKM_EC_KEY_PAIR_GEN, &curveParams,
                           &ephemPubRaw, PR_FALSE, PR_FALSE, nullptr));
  UniqueSECKEYPublicKey ephemPub(ephemPubRaw);

  if (!ephemPriv || !ephemPub) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: PK11_GenerateKeyPair failed."));
    return NS_OK;
  }

  // ── 10. ECDH + ANSI X9.63 KDF → 128-bit AES key ───────────────────────────
  UniquePK11SymKey aesKey(PK11_PubDeriveWithKDF(
      ephemPriv.get(), proxyPubKey,
      PR_FALSE,  // isSender (value ignored for CKM_ECDH1_DERIVE)
      nullptr,   // randomA
      nullptr,   // randomB
      CKM_ECDH1_DERIVE, CKM_AES_GCM, CKA_ENCRYPT,
      16,              // 128-bit key
      CKD_SHA256_KDF,  // ANSI X9.63 with SHA-256
      nullptr,         // sharedData (none)
      nullptr));       // wincx

  if (!aesKey) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: ECDH/KDF failed."));
    return NS_OK;
  }

  // ── 11. Random 12-byte GCM IV ────────────────────────────────────────────
  uint8_t iv[12];
  if (PK11_GenerateRandom(iv, sizeof(iv)) != SECSuccess) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: PK11_GenerateRandom (iv) failed."));
    return NS_OK;
  }

  // ── 12. AES-128-GCM encrypt ──────────────────────────────────────────────
  CK_GCM_PARAMS gcmParams;
  gcmParams.pIv = iv;
  gcmParams.ulIvLen = sizeof(iv);
  gcmParams.ulIvBits = 96;
  gcmParams.pAAD = nullptr;
  gcmParams.ulAADLen = 0;
  gcmParams.ulTagBits = 128;

  SECItem gcmParamItem = {siBuffer, reinterpret_cast<uint8_t*>(&gcmParams),
                          sizeof(gcmParams)};

  uint32_t ptLen = static_cast<uint32_t>(plaintext.Length());
  uint32_t ctBufLen = ptLen + 16;  // plaintext + 16-byte GCM tag
  mozilla::UniquePtr<uint8_t[]> ctBuf(new uint8_t[ctBufLen]);
  uint32_t ctLen = 0;

  SECStatus rv = PK11_Encrypt(
      aesKey.get(), CKM_AES_GCM, &gcmParamItem, ctBuf.get(), &ctLen, ctBufLen,
      reinterpret_cast<const uint8_t*>(plaintext.get()), ptLen);

  if (rv != SECSuccess) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: AES-128-GCM encrypt failed."));
    return NS_OK;
  }

  // ── 13. Assemble token: ephem_pub(65) || IV(12) || ct+tag ────────────────
  const SECItem& pubPt = ephemPub->u.ec.publicValue;  // 65 bytes for P-256
  uint32_t tokenLen = pubPt.len + sizeof(iv) + ctLen;
  mozilla::UniquePtr<uint8_t[]> tokenBuf(new uint8_t[tokenLen]);
  uint8_t* p = tokenBuf.get();
  memcpy(p, pubPt.data, pubPt.len);
  p += pubPt.len;
  memcpy(p, iv, sizeof(iv));
  p += sizeof(iv);
  memcpy(p, ctBuf.get(), ctLen);

  // ── 14. Base64-encode and inject headers ─────────────────────────────────
  nsAutoCString tokenB64;
  nsrv = mozilla::Base64Encode(reinterpret_cast<const char*>(tokenBuf.get()),
                               tokenLen, tokenB64);
  if (NS_FAILED(nsrv)) {
    return NS_OK;
  }

  (void)aHead.SetHeader("X-DenBrowser-Ts"_ns, tsStr, false);
  (void)aHead.SetHeader("X-DenBrowser-Nonce"_ns, nonceB64, false);
  (void)aHead.SetHeader("X-DenBrowser-Token"_ns, tokenB64, false);

  return NS_OK;
}

// ── Proxy SPKI pin verification ──────────────────────────────────────────────
//
// The browser refuses to complete a TLS handshake to a proxy's domain unless
// the leaf cert's SubjectPublicKeyInfo sha256 matches the pin recorded for
// that proxy in the build-time table above.  This shuts off the local-sniffer
// threat: a co-resident attacker on this machine sees only TLS ciphertext
// between the browser and a proxy, and can't impersonate one with a different
// cert (no rogue CA install, no MitM stack, etc.).
//
// Each partner proxy carries its own pin, so rotating one partner's TLS cert
// does not disturb the others — but it does still require a DenBrowser rebuild
// (see the patch header).

// Returns NS_OK and writes 32 bytes of sha256(SubjectPublicKeyInfo) into
// aOut, given the DER bytes of an X.509 certificate.
static nsresult Sha256OfLeafSpki(mozilla::Span<const uint8_t> aCertDer,
                                 uint8_t aOut[32]) {
  if (aCertDer.IsEmpty()) return NS_ERROR_INVALID_ARG;

  SECItem certItem = {siBuffer,
                      const_cast<uint8_t*>(aCertDer.Elements()),
                      static_cast<unsigned int>(aCertDer.Length())};
  // CERT_NewTempCertificate, not CERT_DecodeDERCertificate: the latter is not
  // exported from nss3.dll (absent from security/nss/lib/nss/nss.def), so
  // referencing it fails to link into xul.  This is the same call PSM itself
  // uses to parse a peer cert (see NSSSocketControl.cpp).  copyDER=true so the
  // cert owns its bytes and does not alias aCertDer.
  mozilla::UniqueCERTCertificate cert(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), &certItem, nullptr, false, true));
  if (!cert) return NS_ERROR_FAILURE;

  // Re-encode the parsed SubjectPublicKeyInfo to be sure we hash the full
  // SPKI (algorithm identifier + BIT STRING) per RFC 7469, not just the
  // raw public-key octets.
  SECItem* spkiDer = SEC_ASN1EncodeItem(
      nullptr, nullptr, &cert->subjectPublicKeyInfo,
      SEC_ASN1_GET(CERT_SubjectPublicKeyInfoTemplate));
  if (!spkiDer) return NS_ERROR_FAILURE;

  SECStatus rv =
      PK11_HashBuf(SEC_OID_SHA256, aOut, spkiDer->data, spkiDer->len);
  SECITEM_FreeItem(spkiDer, PR_TRUE);
  return (rv == SECSuccess) ? NS_OK : NS_ERROR_FAILURE;
}

bool VerifyProxyPin(const nsACString& aHost,
                    mozilla::Span<const uint8_t> aLeafCertDer) {
  // Not one of our proxies' domains (or an unconfigured build) → the pin is
  // inert and this host is none of our business.
  int32_t proxyIndex = FindProxyForHost(aHost);
  if (proxyIndex < 0) return true;

  const DenProxyEntry& entry = kDenProxies[proxyIndex];
  if (!entry.mSpkiPin) {
    // Proxy configured without a pin: attestation still applies, but this hop
    // is not bound to a specific server cert.
    MOZ_LOG(sLog, mozilla::LogLevel::Warning,
            ("DenBrowserAttest: proxy \"%s\" has no TLS pin configured — "
             "host=%s is not pin-checked.",
             entry.mName, nsPromiseFlatCString(aHost).get()));
    return true;
  }

  uint8_t hash[32];
  if (NS_FAILED(Sha256OfLeafSpki(aLeafCertDer, hash))) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SPKI hashing failed for host=%s (proxy "
             "\"%s\") — pin REJECT.",
             nsPromiseFlatCString(aHost).get(), entry.mName));
    return false;  // fail-closed
  }

  if (std::memcmp(hash, entry.mSpkiPin, sizeof(hash)) != 0) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SPKI pin MISMATCH for host=%s (proxy \"%s\") "
             "— aborting TLS.",
             nsPromiseFlatCString(aHost).get(), entry.mName));
    return false;
  }
  return true;
}

}  // namespace denbrowser
