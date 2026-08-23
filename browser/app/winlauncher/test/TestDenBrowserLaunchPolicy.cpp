/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <initializer_list>
#include <stdio.h>
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
  ok &= CheckBrowserCommandLine(true, {L"denbrowser.exe", L"-os-restarted"},
                                "Windows restart tag must be accepted");
  ok &= CheckBrowserCommandLine(
      true,
      {L"denbrowser.exe", L"-os-restarted", L"-osint", L"-url",
       L"https://example.test/"},
      "tagged canonical Windows restart must be accepted");

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
