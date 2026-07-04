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
// The proxy private key never appears in this file or the browser binary;
// only the proxy public key (kProxyPublicKeyDer) is embedded.

#include "DenBrowserAttest.h"

#include "cert.h"
#include "certt.h"
#include "keyhi.h"
#include "mozilla/Base64.h"
#include "mozilla/Logging.h"
#include "mozilla/StaticMutex.h"
#include "mozilla/UniquePtr.h"
#include "mozilla/Unused.h"
#include "nsComponentManagerUtils.h"
#include "nsHttp.h"
#include "nsHttpRequestHead.h"
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

namespace denbrowser {

using mozilla::UniqueCERTSubjectPublicKeyInfo;
using mozilla::UniquePK11SlotInfo;
using mozilla::UniquePK11SymKey;
using mozilla::UniqueSECKEYPrivateKey;
using mozilla::UniqueSECKEYPublicKey;

static mozilla::LazyLogModule sLog("DenBrowserAttest");

// ── Proxy public key ──────────────────────────────────────────────────────────
//
// SubjectPublicKeyInfo DER-encoded EC P-256 public key from the DenBrowser
// attestation proxy (Pingora-based; see proxy/).
//
// PLACEHOLDER: all bytes 0x00.  Attestation is DISABLED until replaced.
//
// To generate a keypair and update this array:
//   scripts/gen-attest-key.sh
//
// The matching private key goes to the proxy — it never belongs in this file.
//
// A valid EC P-256 SPKI DER blob is 91 bytes and starts with 0x30.
// The placeholder (all zeros) is detected at startup and skipped silently.

// clang-format off
static const uint8_t kProxyPublicKeyDer[] = {
  // ── REPLACE: paste  xxd -i proxy-public.der  output here ────────────────
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00,
  // ── END REPLACE ───────────────────────────────────────────────────────────
};
// clang-format on

static constexpr uint32_t kProxyPublicKeyDerLen =
    static_cast<uint32_t>(sizeof(kProxyPublicKeyDer));

// Valid P-256 SPKI DER starts with 0x30 (ASN.1 SEQUENCE).
// An all-zero buffer is the placeholder; treat as "not configured".
static bool KeyIsPlaceholder() { return kProxyPublicKeyDer[0] != 0x30; }

// ── TLS-channel pin for the proxy ────────────────────────────────────────────
//
// The browser will refuse to complete a TLS handshake to `kProxyHost` unless
// the leaf cert's SubjectPublicKeyInfo sha256 matches `kProxySpkiSha256`.
// This shuts off the local-sniffer threat: a co-resident attacker on this
// machine sees only TLS ciphertext between the browser and the proxy, and
// can't impersonate the proxy with a different cert (no rogue CA install,
// no MitM stack, etc.).
//
// Defaults below are the unconfigured placeholders.  Running
// scripts/gen-proxy-tls.sh patches in the real values and the pin becomes
// active on the next build.  An empty host or all-zero hash means
// "no pin configured" — VerifyProxyPin returns true and behaves as a no-op.

// ── REPLACE TLS PIN: gen-proxy-tls.sh updates these ─────────────────────
static const char kProxyHost[] = "";
static const uint8_t kProxySpkiSha256[32] = { 0 };
// ── END REPLACE TLS PIN ──────────────────────────────────────────────────

// ── P-256 curve params for ephemeral keygen ───────────────────────────────────
// DER encoding of OID prime256v1 (1.2.840.10045.3.1.7):
//   06 08 2a 86 48 ce 3d 03 01 07
static const uint8_t kP256OidDer[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                      0xce, 0x3d, 0x03, 0x01, 0x07};

// ── Cached proxy public key ───────────────────────────────────────────────────

static mozilla::StaticMutex sKeyMutex;
static SECKEYPublicKey* sProxyPubKey = nullptr;  // process-lifetime; not freed
static bool sKeyLoaded = false;

// Returns the proxy's public key, importing and caching it on first call.
// Returns nullptr if the key is the placeholder or import fails.
static SECKEYPublicKey* GetProxyPublicKey() {
  mozilla::StaticMutexAutoLock lock(sKeyMutex);
  if (sKeyLoaded) return sProxyPubKey;
  sKeyLoaded = true;

  if (KeyIsPlaceholder()) {
    MOZ_LOG(sLog, mozilla::LogLevel::Warning,
            ("DenBrowserAttest: public key is the all-zeros placeholder — "
             "request attestation is DISABLED.  Run "
             "scripts/gen-attest-key.sh, replace kProxyPublicKeyDer[] in "
             "netwerk/base/DenBrowserAttest.cpp, and rebuild."));
    return nullptr;
  }

  SECItem spkiItem = {siBuffer, const_cast<uint8_t*>(kProxyPublicKeyDer),
                      kProxyPublicKeyDerLen};

  UniqueCERTSubjectPublicKeyInfo spki(
      SECKEY_DecodeDERSubjectPublicKeyInfo(&spkiItem));
  if (!spki) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SECKEY_DecodeDERSubjectPublicKeyInfo failed "
             "(bad DER bytes?)."));
    return nullptr;
  }

  SECKEYPublicKey* key = SECKEY_ExtractPublicKey(spki.get());
  if (!key) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SECKEY_ExtractPublicKey failed."));
    return nullptr;
  }

  sProxyPubKey = key;
  return key;
}

// ── Body hashing ──────────────────────────────────────────────────────────────
// Returns lowercase hex SHA-256 of the request body.  Clones the upload stream
// so the original is left untouched and the actual upload sends the same bytes
// the proxy will hash on its side.  On clone failure or null stream, hashes
// the empty string; the proxy will then reject any request with a non-empty
// body (fail-closed by mismatch).

static nsresult HashBody(nsIInputStream* aUploadStream, nsACString& aHexHash) {
  nsCOMPtr<nsICryptoHash> hasher =
      do_CreateInstance("@mozilla.org/security/hash;1");
  if (!hasher) return NS_ERROR_FAILURE;
  nsresult rv = hasher->Init(nsICryptoHash::SHA256);
  NS_ENSURE_SUCCESS(rv, rv);

  if (aUploadStream) {
    nsCOMPtr<nsIInputStream> clone;
    if (NS_SUCCEEDED(NS_CloneInputStream(aUploadStream, getter_AddRefs(clone)))) {
      char buf[4096];
      while (true) {
        uint32_t read = 0;
        rv = clone->Read(buf, sizeof(buf), &read);
        if (NS_FAILED(rv) || read == 0) break;
        rv = hasher->Update(reinterpret_cast<uint8_t*>(buf), read);
        if (NS_FAILED(rv)) break;
      }
    } else {
      MOZ_LOG(sLog, mozilla::LogLevel::Warning,
              ("DenBrowserAttest: upload stream is not cloneable; body hash "
               "will be sha256(\"\") and the proxy will reject."));
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

// ── Public API ────────────────────────────────────────────────────────────────

nsresult AddAttestHeaders(mozilla::net::nsHttpRequestHead& aHead, nsIURI* aURI,
                          nsIInputStream* aUploadStream) {
  MOZ_ASSERT(aURI);

  SECKEYPublicKey* proxyPubKey = GetProxyPublicKey();
  if (!proxyPubKey) {
    return NS_OK;  // Placeholder or load failure — skip silently.
  }

  // ── 1. Timestamp ─────────────────────────────────────────────────────────
  int64_t ts = static_cast<int64_t>(PR_Now() / PR_USEC_PER_SEC);
  nsAutoCString tsStr;
  tsStr.AppendInt(ts);

  // ── 2. Host ──────────────────────────────────────────────────────────────
  // Non-HTTP resources (about:, data:, blob:, …) have no host; skip them.
  nsAutoCString host;
  if (NS_FAILED(aURI->GetAsciiHost(host)) || host.IsEmpty()) {
    return NS_OK;
  }

  // ── 3. Method (already uppercase in nsHttpRequestHead) ───────────────────
  nsAutoCString method;
  aHead.Method(method);

  // ── 4. Path + query (strip fragment; servers never see it) ───────────────
  nsAutoCString path;
  if (NS_FAILED(aURI->GetPathQueryRef(path))) {
    return NS_OK;
  }
  int32_t fragIdx = path.FindChar('#');
  if (fragIdx >= 0) path.Truncate(fragIdx);
  if (path.IsEmpty()) path.AssignLiteral("/");

  // ── 5. Random 16-byte nonce + base64 ─────────────────────────────────────
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

  // ── 6. Body hash (sha256 hex) ────────────────────────────────────────────
  nsAutoCString bodyHex;
  if (NS_FAILED(HashBody(aUploadStream, bodyHex))) {
    return NS_OK;
  }

  // ── 7. Canonical plaintext ───────────────────────────────────────────────
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

  // ── 8. Ephemeral EC P-256 keypair ────────────────────────────────────────
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

  // ── 9. ECDH + ANSI X9.63 KDF → 128-bit AES key ───────────────────────────
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

  // ── 10. Random 12-byte GCM IV ────────────────────────────────────────────
  uint8_t iv[12];
  if (PK11_GenerateRandom(iv, sizeof(iv)) != SECSuccess) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: PK11_GenerateRandom (iv) failed."));
    return NS_OK;
  }

  // ── 11. AES-128-GCM encrypt ──────────────────────────────────────────────
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

  // ── 12. Assemble token: ephem_pub(65) || IV(12) || ct+tag ────────────────
  const SECItem& pubPt = ephemPub->u.ec.publicValue;  // 65 bytes for P-256
  uint32_t tokenLen = pubPt.len + sizeof(iv) + ctLen;
  mozilla::UniquePtr<uint8_t[]> tokenBuf(new uint8_t[tokenLen]);
  uint8_t* p = tokenBuf.get();
  memcpy(p, pubPt.data, pubPt.len);
  p += pubPt.len;
  memcpy(p, iv, sizeof(iv));
  p += sizeof(iv);
  memcpy(p, ctBuf.get(), ctLen);

  // ── 13. Base64-encode and inject headers ─────────────────────────────────
  nsAutoCString tokenB64;
  nsrv = mozilla::Base64Encode(reinterpret_cast<const char*>(tokenBuf.get()),
                               tokenLen, tokenB64);
  if (NS_FAILED(nsrv)) {
    return NS_OK;
  }

  mozilla::Unused << aHead.SetHeader("X-DenBrowser-Ts"_ns, tsStr, false);
  mozilla::Unused << aHead.SetHeader("X-DenBrowser-Nonce"_ns, nonceB64, false);
  mozilla::Unused << aHead.SetHeader("X-DenBrowser-Token"_ns, tokenB64, false);

  return NS_OK;
}

// ── Proxy SPKI pin verification ──────────────────────────────────────────────

static bool PinIsConfigured() {
  if (kProxyHost[0] == '\0') return false;
  for (uint8_t b : kProxySpkiSha256) {
    if (b != 0) return true;
  }
  return false;
}

// Returns NS_OK and writes 32 bytes of sha256(SubjectPublicKeyInfo) into
// aOut, given the DER bytes of an X.509 certificate.
static nsresult Sha256OfLeafSpki(mozilla::Span<const uint8_t> aCertDer,
                                 uint8_t aOut[32]) {
  if (aCertDer.IsEmpty()) return NS_ERROR_INVALID_ARG;

  SECItem certItem = {siBuffer,
                      const_cast<uint8_t*>(aCertDer.Elements()),
                      static_cast<unsigned int>(aCertDer.Length())};
  mozilla::UniqueCERTCertificate cert(
      CERT_DecodeDERCertificate(&certItem, PR_FALSE, nullptr));
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
  // Unconfigured build → pin is inert, every host passes.
  if (!PinIsConfigured()) return true;

  // Pin applies only to the proxy hop; everything else is unaffected.
  if (!aHost.EqualsASCII(kProxyHost)) return true;

  uint8_t hash[32];
  if (NS_FAILED(Sha256OfLeafSpki(aLeafCertDer, hash))) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SPKI hashing failed for host=%s — pin REJECT.",
             nsPromiseFlatCString(aHost).get()));
    return false;  // fail-closed
  }

  if (std::memcmp(hash, kProxySpkiSha256, sizeof(hash)) != 0) {
    MOZ_LOG(sLog, mozilla::LogLevel::Error,
            ("DenBrowserAttest: SPKI pin MISMATCH for host=%s — aborting TLS.",
             nsPromiseFlatCString(aHost).get()));
    return false;
  }
  return true;
}

}  // namespace denbrowser
