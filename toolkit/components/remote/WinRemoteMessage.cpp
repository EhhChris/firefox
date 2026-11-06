/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsCommandLine.h"
#include "mozilla/CmdLineAndEnvUtils.h"
#include "mozilla/Span.h"
#include "mozilla/Try.h"
#include "mozilla/Utf8.h"
#include "DenBrowserLaunchPolicy.h"
#include "WinRemoteMessage.h"

using namespace mozilla;

#define MOZ_MAGIC_COPYDATA_PREFIX "🔥🦊"

// DenBrowser: any process running as this user can send WM_COPYDATA to the
// remote window, so a forwarded command line must pass the launcher's grammar
// (patch 015) instead of being trusted. A second, launcher-approved instance
// forwards exactly that shape, with any den: link already unwrapped, so a
// den: link is refused here. Arguments must be valid UTF-8.
static bool IsAllowedDenBrowserRemoteArguments(
    const nsTArray<const char*>& aArgv) {
  // The grammar never has more than four arguments; skip converting a flood.
  if (aArgv.Length() > 4) {
    return false;
  }

  AutoTArray<nsString, 4> wideArgs;
  for (const char* arg : aArgv) {
    if (!IsUtf8(MakeStringSpan(arg))) {
      return false;
    }
    wideArgs.AppendElement(NS_ConvertUTF8toUTF16(arg));
  }

  AutoTArray<const wchar_t*, 4> wideArgv;
  for (const nsString& arg : wideArgs) {
    wideArgv.AppendElement(static_cast<const wchar_t*>(arg.get()));
  }
  return denbrowser::IsAllowedBrowserCommandLine(
      static_cast<int>(wideArgv.Length()), wideArgv.Elements());
}

WinRemoteMessageSender::WinRemoteMessageSender(int32_t aArgc,
                                               const char** aArgv,
                                               const nsAString& aWorkingDir)
    : mData({static_cast<DWORD>(
          WinRemoteMessageVersion::NullSeparatedArguments)}) {
  mCmdLineBuffer.AppendLiteral(MOZ_MAGIC_COPYDATA_PREFIX "\0");
  AppendUTF16toUTF8(aWorkingDir, mCmdLineBuffer);
  mCmdLineBuffer.Append('\0');

  for (int32_t i = 0; i < aArgc; i++) {
    mCmdLineBuffer.Append(aArgv[i]);
    mCmdLineBuffer.Append('\0');
  }

  char* mutableBuffer;
  mData.cbData = mCmdLineBuffer.GetMutableData(&mutableBuffer);
  mData.lpData = mutableBuffer;
}

COPYDATASTRUCT* WinRemoteMessageSender::CopyData() { return &mData; }

nsresult WinRemoteMessageReceiver::ParseV2(const nsAString& aBuffer) {
  CommandLineParserWin<char16_t> parser;
  size_t cch = parser.HandleCommandLine(aBuffer);
  ++cch;  // skip a null char

  nsCOMPtr<nsIFile> workingDir;
  if (cch < aBuffer.Length()) {
    MOZ_TRY(
        NS_NewLocalFile(Substring(aBuffer, cch), getter_AddRefs(workingDir)));
  }

  int argc = parser.Argc();
  Vector<nsAutoCString> utf8args;
  if (!utf8args.reserve(argc)) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  UniquePtr<const char*[]> argv(new const char*[argc]);
  for (int i = 0; i < argc; ++i) {
    utf8args.infallibleAppend(NS_ConvertUTF16toUTF8(parser.Argv()[i]));
    argv[i] = utf8args[i].get();
  }

  mCommandLine = new nsCommandLine();
  return mCommandLine->Init(argc, argv.get(), workingDir,
                            nsICommandLine::STATE_REMOTE_AUTO);
}

nsresult WinRemoteMessageReceiver::ParseV3(const nsACString& aBuffer) {
  // String should start with the magic sequence followed by null
  int32_t nextNul = aBuffer.FindChar('\0');
  if (nextNul < 0) {
    return NS_ERROR_FAILURE;
  }

  if (!Substring(aBuffer, 0, nextNul).Equals(MOZ_MAGIC_COPYDATA_PREFIX)) {
    return NS_ERROR_FAILURE;
  }

  int32_t pos = nextNul + 1;
  nextNul = aBuffer.FindChar('\0', pos);
  if (nextNul < 0) {
    return NS_ERROR_FAILURE;
  }

  // DenBrowser: the sender's working directory is skipped. The launch grammar
  // never needs it, and resolving -url against it would make the browser open
  // a path of the sender's choosing, such as a UNC share.

  pos = nextNul + 1;
  nsTArray<const char*> argv;

  while (true) {
    nextNul = aBuffer.FindChar('\0', pos);
    if (nextNul < 0) {
      break;
    }

    // Because each argument is null terminated we can just add the pointer to
    // the array directly.
    argv.AppendElement(aBuffer.BeginReading() + pos);
    pos = nextNul + 1;
  }

  // There should always be at least one argument, the path to the binary.
  if (argv.IsEmpty()) {
    return NS_ERROR_FAILURE;
  }

  if (!IsAllowedDenBrowserRemoteArguments(argv)) {
    return NS_ERROR_FAILURE;
  }

  mCommandLine = new nsCommandLine();
  return mCommandLine->Init(argv.Length(), argv.Elements(), nullptr,
                            nsICommandLine::STATE_REMOTE_AUTO);
}

nsresult WinRemoteMessageReceiver::Parse(const COPYDATASTRUCT* aMessageData) {
  switch (static_cast<WinRemoteMessageVersion>(aMessageData->dwData)) {
    case WinRemoteMessageVersion::CommandLineAndWorkingDirInUtf16:
      // DenBrowser: no DenBrowser build sends ESR 128's v2 format, and only
      // v3 is checked against the launch grammar, so v2 is refused.
      return NS_ERROR_FAILURE;
    case WinRemoteMessageVersion::NullSeparatedArguments:
      return ParseV3(nsDependentCSubstring(
          reinterpret_cast<char*>(aMessageData->lpData), aMessageData->cbData));
    default:
      MOZ_ASSERT_UNREACHABLE("Unsupported message version");
      return NS_ERROR_FAILURE;
  }
}

nsICommandLineRunner* WinRemoteMessageReceiver::CommandLineRunner() {
  return mCommandLine;
}

#undef MOZ_MAGIC_COPYDATA_PREFIX
