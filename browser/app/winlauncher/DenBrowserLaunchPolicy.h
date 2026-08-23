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

// The public Windows launch language is intentionally tiny:
//   denbrowser.exe
//   denbrowser.exe -osint -url http(s)://...
// Windows Restart Manager may prepend one exact, advisory -os-restarted tag.
// That tag never grants access to any additional argument or environment state.
inline bool IsAllowedBrowserCommandLine(int aArgc, wchar_t* const aArgv[]) {
  if (aArgc < 1 || !aArgv || !aArgv[0]) {
    return false;
  }

  int index = 1;
  if (index < aArgc && aArgv[index] &&
      !wcscmp(aArgv[index], L"-os-restarted")) {
    ++index;
  }

  if (index == aArgc) {
    return true;
  }

  return aArgc - index == 3 && aArgv[index] && aArgv[index + 1] &&
         aArgv[index + 2] && !wcscmp(aArgv[index], L"-osint") &&
         !wcscmp(aArgv[index + 1], L"-url") &&
         IsAllowedWebUrl(aArgv[index + 2]);
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
