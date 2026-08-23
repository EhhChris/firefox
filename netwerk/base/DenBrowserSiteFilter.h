/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef DenBrowserSiteFilter_h__
#define DenBrowserSiteFilter_h__

#include <cstddef>

#include "nsIURI.h"
#include "nsString.h"

namespace denbrowser {

// Compile-time whitelist/blacklist. build.sh injects entries from
// site-config.json between the sentinel markers at build time.
//
// Whitelist takes priority. With no whitelist, blacklist entries are denied.
// Both empty means no filtering.
// ── DEN: SITE_WHITELIST ──
static const char* const kDenSiteWhitelist[] = {nullptr};
// ── DEN END: SITE_WHITELIST ──
// ── DEN: SITE_BLACKLIST ──
static const char* const kDenSiteBlacklist[] = {nullptr};
// ── DEN END: SITE_BLACKLIST ──

inline bool SiteHostMatches(const nsACString& aHost, const char* aPattern) {
  nsDependentCString pattern(aPattern);
  if (aHost.Equals(pattern)) return true;
  if (aHost.Length() > pattern.Length() + 1) {
    return aHost.CharAt(aHost.Length() - pattern.Length() - 1) == '.' &&
           Substring(aHost, aHost.Length() - pattern.Length()).Equals(pattern);
  }
  return false;
}

inline bool SiteAllowed(nsIURI* aURI) {
  if (!aURI) return false;

  nsAutoCString scheme;
  if (NS_FAILED(aURI->GetScheme(scheme))) return false;
  if (!scheme.EqualsLiteral("http") && !scheme.EqualsLiteral("https")) {
    return true;
  }

  nsAutoCString host;
  if (NS_FAILED(aURI->GetAsciiHost(host)) || host.IsEmpty()) return false;

  if (kDenSiteWhitelist[0]) {
    for (size_t i = 0; kDenSiteWhitelist[i]; ++i) {
      if (SiteHostMatches(host, kDenSiteWhitelist[i])) return true;
    }
    return false;
  }

  for (size_t i = 0; kDenSiteBlacklist[i]; ++i) {
    if (SiteHostMatches(host, kDenSiteBlacklist[i])) return false;
  }
  return true;
}

}  // namespace denbrowser

#endif  // DenBrowserSiteFilter_h__
