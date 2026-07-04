/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef DenBrowserAttest_h__
#define DenBrowserAttest_h__

#include "nscore.h"
#include "mozilla/Span.h"
#include "nsStringFwd.h"

class nsIInputStream;
class nsIURI;
namespace mozilla::net {
class nsHttpRequestHead;
}

namespace denbrowser {

/**
 * AddAttestHeaders — inject X-DenBrowser-Ts, X-DenBrowser-Nonce, and X-DenBrowser-Token
 * into aHead for every outbound HTTP/HTTPS request.
 *
 * Called from nsHttpChannel::SetupChannelForTransaction().  The token is an
 * ECIES-encrypted payload that decrypts (using the matching private key held
 * by the attestation proxy) to a canonical plaintext that binds the request
 * to its method, host, path, and body hash.  A captured token cannot be
 * replayed against a different request because every field is in the
 * authenticated plaintext, and the per-request nonce is rejected by the
 * proxy's replay cache on the second use.
 *
 * Protocol:  ECIES with EC P-256, ANSI X9.63 KDF (SHA-256), AES-128-GCM.
 *
 * Canonical plaintext (v2):
 *   "denbrowser-attest:v2\n<nonce_b64>\n<ts>\n<host>\n<method>\n<path>\n<sha256_hex>"
 *
 * Key model:
 *   - The attestation proxy holds the EC P-256 private key.
 *   - Each DenBrowser build embeds only the matching SPKI public key.
 *   - A new keypair per browser release lets the proxy invalidate old builds
 *     by rotating its private key or removing the old public key from its
 *     allowlist.
 *
 * Behaviour when not configured:
 *   If the embedded public key is the all-zeros placeholder, this function
 *   is a silent no-op.  No request is ever blocked by this code.
 *
 * Thread-safety:
 *   The public key is imported from DER at most once per process and cached.
 *   Safe to call from any thread that can already call nsHttpChannel methods.
 */
nsresult AddAttestHeaders(mozilla::net::nsHttpRequestHead& aHead, nsIURI* aURI,
                          nsIInputStream* aUploadStream);

/**
 * VerifyProxyPin — return false to abort a TLS handshake when the peer
 * claims to be our attestation proxy but presents the wrong public key.
 *
 * Called from SSLServerCertVerification.cpp::AuthCertificateHook before any
 * application data flows.  Behaviour:
 *
 *   - If the build is unconfigured (kProxyHost empty or kProxySpkiSha256
 *     all-zero), returns true unconditionally.  Dev builds work normally.
 *   - If `aHost` is not the configured proxy host, returns true (this
 *     function only constrains the proxy hop, not other TLS connections).
 *   - Otherwise, decodes `aLeafCertDer`, computes sha256(SubjectPublicKeyInfo),
 *     and returns true iff it matches kProxySpkiSha256.
 *
 * On any decode/hash failure with a configured pin, returns false
 * (fail-closed: a broken cert isn't allowed to bypass the pin).
 */
bool VerifyProxyPin(const nsACString& aHost,
                    mozilla::Span<const uint8_t> aLeafCertDer);

}  // namespace denbrowser

#endif  // DenBrowserAttest_h__
