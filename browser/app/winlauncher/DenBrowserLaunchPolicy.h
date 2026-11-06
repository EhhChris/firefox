/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef mozilla_DenBrowserLaunchPolicy_h
#define mozilla_DenBrowserLaunchPolicy_h

#include <stddef.h>
#include <wchar.h>

namespace mozilla::denbrowser {

constexpr size_t kMaximumLaunchUrlLength = 8192;

inline bool IsAllowedWebUrl(const wchar_t* aValue) {
  if (!aValue) {
    return false;
  }

  size_t length = 0;
  while (aValue[length] && length <= kMaximumLaunchUrlLength) {
    wchar_t ch = aValue[length++];
    if (ch <= 0x20 || ch == 0x7f || ch == L'"' || ch == L'<' || ch == L'>' ||
        ch == L'\\') {
      return false;
    }
  }
  if (!length || length > kMaximumLaunchUrlLength) {
    return false;
  }

  size_t schemeLength = 0;
  if (length >= 7 && !_wcsnicmp(aValue, L"http://", 7)) {
    schemeLength = 7;
  } else if (length >= 8 && !_wcsnicmp(aValue, L"https://", 8)) {
    schemeLength = 8;
  } else {
    return false;
  }

  const wchar_t* authority = aValue + schemeLength;
  const wchar_t* authorityEnd = authority;
  while (*authorityEnd && *authorityEnd != L'/' && *authorityEnd != L'?' &&
         *authorityEnd != L'#') {
    if (*authorityEnd == L'@') {
      // Userinfo makes a command-line URL visually ambiguous and is not needed
      // by the managed browser deployment.
      return false;
    }
    ++authorityEnd;
  }

  if (authorityEnd == authority || *authority == L':') {
    return false;
  }

  if (*authority == L'[') {
    const wchar_t* closingBracket = authority + 1;
    while (closingBracket < authorityEnd && *closingBracket != L']') {
      ++closingBracket;
    }
    if (closingBracket == authorityEnd || closingBracket == authority + 1) {
      return false;
    }
  }

  return true;
}

// A den: link wraps one URL as den:<url> or den://<url>. Returns the wrapped
// URL without validating it, or nullptr when aValue is not a den: link.
inline wchar_t* UnwrapDenLinkUrl(wchar_t* aValue) {
  if (!aValue || _wcsnicmp(aValue, L"den:", 4)) {
    return nullptr;
  }

  wchar_t* inner = aValue + 4;
  if (inner[0] == L'/' && inner[1] == L'/') {
    inner += 2;
  }
  return inner;
}

// Replaces a den: link in the trailing "-osint -url <url>" position with the
// URL it wraps. IsAllowedBrowserCommandLine still decides afterwards.
inline void UnwrapDenLinkArgument(int aArgc, wchar_t* aArgv[]) {
  if (aArgc < 4 || !aArgv || !aArgv[aArgc - 3] || !aArgv[aArgc - 2] ||
      wcscmp(aArgv[aArgc - 3], L"-osint") ||
      wcscmp(aArgv[aArgc - 2], L"-url")) {
    return;
  }

  if (wchar_t* inner = UnwrapDenLinkUrl(aArgv[aArgc - 1])) {
    aArgv[aArgc - 1] = inner;
  }
}

// The public Windows launch language is intentionally tiny:
//   denbrowser.exe
//   denbrowser.exe -osint -url http(s)://...
// A registered den: link arrives as -osint -url den:http(s)://... and is
// reduced to the second form by UnwrapDenLinkArgument before this check.
// Nothing else is accepted, including the -os-restarted tag of Windows Restart
// Manager relaunches: DenBrowser locks toolkit.winRegisterApplicationRestart
// off, so it never registers one. The binary path in argv[0] is not inspected.
// Patch 026 applies this same check to command lines forwarded to a running
// browser, so any widening here widens that channel too.
inline bool IsAllowedBrowserCommandLine(int aArgc,
                                        const wchar_t* const aArgv[]) {
  if (aArgc < 1 || !aArgv || !aArgv[0]) {
    return false;
  }

  if (aArgc == 1) {
    return true;
  }

  return aArgc == 4 && aArgv[1] && aArgv[2] && aArgv[3] &&
         !wcscmp(aArgv[1], L"-osint") && !wcscmp(aArgv[2], L"-url") &&
         IsAllowedWebUrl(aArgv[3]);
}

inline bool IsContentProcessFlag(const wchar_t* aArg) {
  if (!aArg) {
    return false;
  }

  if (*aArg == L'/') {
    ++aArg;
  } else if (*aArg == L'-') {
    ++aArg;
    if (*aArg == L'-') {
      ++aArg;
    }
  } else {
    return false;
  }

  return !_wcsicmp(aArg, L"contentproc");
}

inline bool HasContentProcessFlag(int aArgc, wchar_t* const aArgv[]) {
  for (int i = 1; i < aArgc; ++i) {
    if (IsContentProcessFlag(aArgv[i])) {
      return true;
    }
  }
  return false;
}

inline bool IsCanonicalContentProcessCommandLine(int aArgc,
                                                 wchar_t* const aArgv[]) {
  if (aArgc < 4 || !aArgv || !aArgv[1] || wcscmp(aArgv[1], L"-contentproc")) {
    return false;
  }

  for (int i = 2; i < aArgc; ++i) {
    if (IsContentProcessFlag(aArgv[i])) {
      return false;
    }
  }
  return true;
}

}  // namespace mozilla::denbrowser

#endif  // mozilla_DenBrowserLaunchPolicy_h
