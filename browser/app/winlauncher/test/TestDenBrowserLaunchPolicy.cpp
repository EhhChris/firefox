/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <initializer_list>
#include <stdio.h>
#include <string>
#include <vector>

#include "DenBrowserLaunchPolicy.h"

static bool CheckBrowserCommandLine(
    bool aExpected, std::initializer_list<const wchar_t*> aArguments,
    const char* aDescription) {
  std::vector<wchar_t*> argv;
  for (const wchar_t* argument : aArguments) {
    argv.push_back(const_cast<wchar_t*>(argument));
  }

  bool actual = mozilla::denbrowser::IsAllowedBrowserCommandLine(
      static_cast<int>(argv.size()), argv.data());
  if (actual != aExpected) {
    printf("TEST-FAILED | DenBrowserLaunchPolicy | %s\n", aDescription);
    return false;
  }
  return true;
}

// aExpectedUrl is the URL the browser must receive, or nullptr when the
// launch must be rejected.
static bool CheckDenLink(std::initializer_list<const wchar_t*> aArguments,
                         const wchar_t* aExpectedUrl,
                         const char* aDescription) {
  std::vector<wchar_t*> argv;
  for (const wchar_t* argument : aArguments) {
    argv.push_back(const_cast<wchar_t*>(argument));
  }

  int argc = static_cast<int>(argv.size());
  mozilla::denbrowser::UnwrapDenLinkArgument(argc, argv.data());
  bool allowed =
      mozilla::denbrowser::IsAllowedBrowserCommandLine(argc, argv.data());
  bool ok = aExpectedUrl ? allowed && !wcscmp(argv.back(), aExpectedUrl)
                         : !allowed;
  if (!ok) {
    printf("TEST-FAILED | DenBrowserLaunchPolicy | %s\n", aDescription);
  }
  return ok;
}

static bool CheckContentCommandLine(
    bool aExpected, std::initializer_list<const wchar_t*> aArguments,
    const char* aDescription) {
  std::vector<wchar_t*> argv;
  for (const wchar_t* argument : aArguments) {
    argv.push_back(const_cast<wchar_t*>(argument));
  }

  bool actual = mozilla::denbrowser::IsCanonicalContentProcessCommandLine(
      static_cast<int>(argv.size()), argv.data());
  if (actual != aExpected) {
    printf("TEST-FAILED | DenBrowserLaunchPolicy | %s\n", aDescription);
    return false;
  }
  return true;
}

extern "C" int wmain() {
  bool ok = true;

  ok &= CheckBrowserCommandLine(true, {L"denbrowser.exe"},
                                "no-argument launch must be accepted");
  ok &= CheckBrowserCommandLine(
      true, {L"denbrowser.exe", L"-osint", L"-url", L"https://example.test/a"},
      "canonical HTTPS OS launch must be accepted");
  ok &= CheckBrowserCommandLine(
      true, {L"denbrowser.exe", L"-osint", L"-url", L"http://example.test/"},
      "canonical HTTP OS launch must be accepted");
  ok &= CheckBrowserCommandLine(
      true, {L""}, "binary path in argv[0] is not inspected");

  ok &= CheckBrowserCommandLine(false, {}, "empty argument list must be rejected");
  ok &= CheckBrowserCommandLine(false, {nullptr},
                                "null argv[0] must be rejected");
  ok &= CheckBrowserCommandLine(false, {L"denbrowser.exe", L"-os-restarted"},
                                "Windows restart tag must be rejected");
  ok &= CheckBrowserCommandLine(
      false,
      {L"denbrowser.exe", L"-os-restarted", L"-osint", L"-url",
       L"https://example.test/"},
      "tagged Windows restart must be rejected");
  ok &= CheckBrowserCommandLine(
      false,
      {L"denbrowser.exe", L"-private-window", L"-url", L"https://example.test/"},
      "flag in place of -osint must be rejected");
  ok &= CheckBrowserCommandLine(
      false,
      {L"denbrowser.exe", L"-osint", L"-new-window", L"https://example.test/"},
      "flag in place of -url must be rejected");
  ok &= CheckBrowserCommandLine(
      false, {L"denbrowser.exe", L"-url", L"https://example.test/"},
      "-url without -osint must be rejected");
  ok &= CheckBrowserCommandLine(false, {L"denbrowser.exe", L"-osint", L"-url"},
                                "-url without a value must be rejected");
  ok &= CheckBrowserCommandLine(
      false, {L"denbrowser.exe", L"-osint", L"-url", nullptr},
      "null URL must be rejected");
  ok &= CheckBrowserCommandLine(
      false,
      {L"denbrowser.exe", L"-osint", L"-url", L"den:https://example.test/"},
      "den: link that was not unwrapped must be rejected");

  ok &= CheckBrowserCommandLine(false,
                                {L"denbrowser.exe", L"https://example.test/"},
                                "bare URL must be rejected");
  ok &= CheckBrowserCommandLine(
      false, {L"denbrowser.exe", L"-xpcshell", L"-e", L"print('unexpected')"},
      "xpcshell dispatch must be rejected");
  ok &=
      CheckBrowserCommandLine(false, {L"denbrowser.exe", L"--MOZ_LOG=Logger:5"},
                              "logging alias must be rejected");
  ok &= CheckBrowserCommandLine(
      false, {L"denbrowser.exe", L"-osint", L"-url", L"file:///C:/secret.txt"},
      "file URL must be rejected");
  ok &= CheckBrowserCommandLine(
      false,
      {L"denbrowser.exe", L"-osint", L"-url", L"https://user@example.test/"},
      "URL userinfo must be rejected");
  ok &= CheckBrowserCommandLine(false,
                                {L"denbrowser.exe", L"-osint", L"-url",
                                 L"https://example.test/", L"--headless"},
                                "extra argument must be rejected");
  ok &= CheckBrowserCommandLine(
      false, {L"denbrowser.exe", L"-os-restarted", L"-os-restarted"},
      "duplicate restart tags must be rejected");

  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:https://example.test/a"},
      L"https://example.test/a", "den: link must unwrap to its HTTPS URL");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den://https://example.test/a"},
      L"https://example.test/a", "den:// link must unwrap to its HTTPS URL");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:http://example.test/"},
      L"http://example.test/", "den: link must unwrap to its HTTP URL");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"DEN:https://example.test/"},
      L"https://example.test/", "den: scheme must match case-insensitively");
  ok &= CheckDenLink({L"denbrowser.exe", L"-os-restarted", L"-osint", L"-url",
                      L"den:https://example.test/"},
                     nullptr, "tagged restart den: link must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"https://example.test/"},
      L"https://example.test/", "plain URL must pass through unchanged");

  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:file:///C:/secret.txt"},
      nullptr, "den: link to a file URL must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den://javascript:alert(1)"},
      nullptr, "den: link to a javascript URL must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:about:config"}, nullptr,
      "den: link to an about URL must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:den:https://example.test/"},
      nullptr, "nested den: link must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url",
                      L"den://den://https://example.test/"},
                     nullptr, "nested den:// link must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url",
                      L"den:///https://example.test/"},
                     nullptr, "den:/// link must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:https%3A%2F%2Fexample.test"},
      nullptr, "percent-encoded den: link must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:https://user@example.test/"},
      nullptr, "den: link with URL userinfo must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url", L"den:"}, nullptr,
                     "empty den: link must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url", L"den://"},
                     nullptr, "empty den:// link must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url", L"den:https://"},
                     nullptr, "den: link without a host must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"den:https://example.test/"}, nullptr,
                     "bare den: link must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-osint", L"-url",
                      L"den:https://example.test/", L"--headless"},
                     nullptr, "den: link with an extra argument must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"--headless", L"-osint", L"-url",
                      L"den:https://example.test/"},
                     nullptr, "den: link after an extra argument must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"den:https://example.test/",
                      L"-osint", L"-url", L"https://example.test/"},
                     nullptr, "den: link before the -osint pair must be rejected");
  ok &= CheckDenLink({L"denbrowser.exe", L"-os-restarted",
                      L"den:https://example.test/"},
                     nullptr, "den: link after a bare restart tag must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"--osint", L"--url", L"den:https://example.test/"},
      nullptr, "den: link with double-dash flags must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"/osint", L"/url", L"den:https://example.test/"},
      nullptr, "den: link with slash flags must be rejected");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", L"den:\thttps://example.test/"},
      nullptr, "den: link with a tab after the prefix must be rejected");

  const std::wstring longestUrl =
      L"https://example.test/" +
      std::wstring(mozilla::denbrowser::kMaximumLaunchUrlLength - 21, L'a');
  const std::wstring longestLink = L"den://" + longestUrl;
  const std::wstring tooLongLink = longestLink + L"a";
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", longestLink.c_str()},
      longestUrl.c_str(), "den:// link to a maximum-length URL must unwrap");
  ok &= CheckDenLink(
      {L"denbrowser.exe", L"-osint", L"-url", tooLongLink.c_str()}, nullptr,
      "den:// link to an over-length URL must be rejected");

  ok &= CheckContentCommandLine(
      true, {L"denbrowser.exe", L"-contentproc", L"1", L"tab"},
      "canonical child shape must be recognized");
  ok &= CheckContentCommandLine(
      false, {L"denbrowser.exe", L"--contentproc", L"1", L"tab"},
      "alternate child flag spelling must be rejected");
  ok &= CheckContentCommandLine(
      false, {L"denbrowser.exe", L"value", L"-contentproc", L"1", L"tab"},
      "misplaced child flag must be rejected");
  ok &= CheckContentCommandLine(
      false,
      {L"denbrowser.exe", L"-contentproc", L"-contentproc", L"1", L"tab"},
      "duplicate child flag must be rejected");

  return ok ? 0 : 1;
}
