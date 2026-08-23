/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "LauncherProcessWin.h"
#include "DenBrowserLaunchPolicy.h"

#include "mozilla/CmdLineAndEnvUtils.h"
#include "mozilla/DebugOnly.h"
#include "mozilla/DenBrowserProcessSecurity.h"
#include "mozilla/glue/Debug.h"
#include "mozilla/GeckoArgs.h"
#include "mozilla/Maybe.h"
#include "mozilla/NativeNt.h"
#include "mozilla/SafeMode.h"
#include "mozilla/UniquePtr.h"
#include "mozilla/WindowsConsole.h"
#include "mozilla/WindowsProcessMitigations.h"
#include "mozilla/WindowsVersion.h"
#include "mozilla/WinHeaderOnlyUtils.h"
#include "nsWindowsHelpers.h"

#include <windows.h>
#include <processthreadsapi.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <algorithm>
#include <iterator>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <utility>
#include <vector>

#include "DllBlocklistInit.h"
#include "ErrorHandler.h"
#include "LaunchUnelevated.h"
#include "ProcThreadAttributes.h"
#include "../BrowserDefines.h"

#if defined(MOZ_LAUNCHER_PROCESS)
#  include "mozilla/LauncherRegistryInfo.h"
#  include "SameBinary.h"
#endif  // defined(MOZ_LAUNCHER_PROCESS)

#if defined(MOZ_SANDBOX)
#  include "mozilla/sandboxing/SandboxInitialization.h"
#endif

namespace mozilla {
// "const" because nothing in this process modifies it.
// "volatile" because something in another process may.
const volatile DeelevationStatus gDeelevationStatus =
    DeelevationStatus::DefaultStaticValue;
const volatile DenBrowserLaunchAuthorization gDenBrowserLaunchAuthorization =
    DenBrowserLaunchAuthorization::Untrusted;
}  // namespace mozilla

using DenBrowserEnvironmentEntry = std::pair<std::wstring, std::wstring>;
using DenBrowserEnvironment = std::vector<DenBrowserEnvironmentEntry>;

static bool DenBrowserGetKnownFolder(REFKNOWNFOLDERID aFolder, HANDLE aToken,
                                     std::wstring& aPath) {
  wchar_t* rawPath = nullptr;
  HRESULT result =
      ::SHGetKnownFolderPath(aFolder, KF_FLAG_DONT_VERIFY, aToken, &rawPath);
  if (FAILED(result) || !rawPath || !*rawPath) {
    if (rawPath) {
      ::CoTaskMemFree(rawPath);
    }
    return false;
  }

  aPath.assign(rawPath);
  ::CoTaskMemFree(rawPath);
  return true;
}

static bool DenBrowserGetApplicationDirectory(const wchar_t* aBinaryPath,
                                              std::wstring& aDirectory) {
  if (!aBinaryPath || !*aBinaryPath) {
    return false;
  }

  aDirectory.assign(aBinaryPath);
  size_t separator = aDirectory.find_last_of(L"\\/");
  if (separator == std::wstring::npos || separator < 2) {
    return false;
  }
  aDirectory.resize(separator);
  return aDirectory.find(L';') == std::wstring::npos;
}

static bool DenBrowserBuildEnvironment(
    HANDLE aToken, const std::wstring& aApplicationDirectory,
    DenBrowserEnvironment& aEnvironment) {
  wchar_t windowsBuffer[MAX_PATH + 1] = {};
  UINT windowsLength =
      ::GetWindowsDirectoryW(windowsBuffer, std::size(windowsBuffer));
  if (!windowsLength || windowsLength >= std::size(windowsBuffer)) {
    return false;
  }

  wchar_t systemBuffer[MAX_PATH + 1] = {};
  UINT systemLength =
      ::GetSystemDirectoryW(systemBuffer, std::size(systemBuffer));
  if (!systemLength || systemLength >= std::size(systemBuffer)) {
    return false;
  }

  std::wstring windowsDirectory(windowsBuffer, windowsLength);
  if (windowsDirectory.size() < 3 || windowsDirectory[1] != L':') {
    return false;
  }

  std::wstring localAppData;
  if (!DenBrowserGetKnownFolder(FOLDERID_LocalAppData, aToken, localAppData)) {
    return false;
  }

  std::wstring programFiles;
  if (!DenBrowserGetKnownFolder(FOLDERID_ProgramFiles, aToken, programFiles)) {
    return false;
  }

  std::wstring path = aApplicationDirectory;
  path.append(L";").append(systemBuffer).append(L";").append(windowsBuffer);
  std::wstring temp = localAppData;
  temp.append(L"\\Temp");

  aEnvironment.clear();
  aEnvironment.reserve(8);
  aEnvironment.emplace_back(L"LOCALAPPDATA", std::move(localAppData));
  aEnvironment.emplace_back(L"Path", std::move(path));
  aEnvironment.emplace_back(L"ProgramFiles", programFiles);
  aEnvironment.emplace_back(L"ProgramW6432", std::move(programFiles));
  aEnvironment.emplace_back(L"SystemDrive", windowsDirectory.substr(0, 2));
  aEnvironment.emplace_back(L"SystemRoot", std::move(windowsDirectory));
  aEnvironment.emplace_back(L"TEMP", temp);
  aEnvironment.emplace_back(L"TMP", std::move(temp));

  std::sort(aEnvironment.begin(), aEnvironment.end(),
            [](const DenBrowserEnvironmentEntry& aLeft,
               const DenBrowserEnvironmentEntry& aRight) {
              return _wcsicmp(aLeft.first.c_str(), aRight.first.c_str()) < 0;
            });
  for (size_t i = 1; i < aEnvironment.size(); ++i) {
    if (!_wcsicmp(aEnvironment[i - 1].first.c_str(),
                  aEnvironment[i].first.c_str())) {
      return false;
    }
  }
  return true;
}

static mozilla::UniquePtr<wchar_t[]> DenBrowserSerializeEnvironment(
    const DenBrowserEnvironment& aEnvironment) {
  size_t totalLength = 1;
  for (const auto& [name, value] : aEnvironment) {
    if (name.empty() || name.find(L'=') != std::wstring::npos) {
      return nullptr;
    }
    size_t entryLength = name.size() + 1 + value.size() + 1;
    if (entryLength > 32767 || totalLength > 32767 - entryLength) {
      return nullptr;
    }
    totalLength += entryLength;
  }

  auto block = mozilla::MakeUnique<wchar_t[]>(totalLength);
  if (!block) {
    return nullptr;
  }

  wchar_t* cursor = block.get();
  for (const auto& [name, value] : aEnvironment) {
    wmemcpy(cursor, name.c_str(), name.size());
    cursor += name.size();
    *cursor++ = L'=';
    wmemcpy(cursor, value.c_str(), value.size());
    cursor += value.size();
    *cursor++ = L'\0';
  }
  *cursor = L'\0';
  return block;
}

static bool DenBrowserWideToUtf8(const std::wstring& aValue,
                                 std::string& aResult) {
  if (aValue.empty()) {
    aResult.clear();
    return true;
  }

  if (aValue.size() > 32767) {
    return false;
  }
  int inputLength = static_cast<int>(aValue.size());
  int length =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, aValue.c_str(),
                            inputLength, nullptr, 0, nullptr, nullptr);
  if (length <= 0) {
    return false;
  }
  aResult.resize(length);
  return ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, aValue.c_str(),
                               inputLength, aResult.data(), length, nullptr,
                               nullptr) == length;
}

static bool DenBrowserApplyCurrentEnvironment(
    const DenBrowserEnvironment& aEnvironment) {
  // Clear the CRT's narrow environment before setting approved values. This is
  // what early EnvHasValue/getenv consumers read in the launcher.
  std::vector<std::string> narrowNames;
  for (char** item = _environ; item && *item; ++item) {
    const char* separator = strchr(*item, '=');
    if (separator && separator != *item) {
      narrowNames.emplace_back(*item, separator - *item);
    }
  }
  for (const std::string& name : narrowNames) {
    if (_putenv_s(name.c_str(), "")) {
      return false;
    }
  }

  // Clear the native Unicode environment as well. Pseudo drive-current-
  // directory entries begin with '='; they are omitted from the explicit
  // browser environment block and are not valid SetEnvironmentVariable names.
  wchar_t* rawEnvironment = ::GetEnvironmentStringsW();
  if (!rawEnvironment) {
    return false;
  }
  std::vector<std::wstring> wideNames;
  for (const wchar_t* item = rawEnvironment; *item; item += wcslen(item) + 1) {
    const wchar_t* separator = wcschr(item, L'=');
    if (separator && separator != item) {
      wideNames.emplace_back(item, separator - item);
    }
  }
  ::FreeEnvironmentStringsW(rawEnvironment);
  for (const std::wstring& name : wideNames) {
    if (!::SetEnvironmentVariableW(name.c_str(), nullptr)) {
      return false;
    }
  }

  for (const auto& [name, value] : aEnvironment) {
    std::string narrowName;
    std::string narrowValue;
    if (!DenBrowserWideToUtf8(name, narrowName) ||
        !DenBrowserWideToUtf8(value, narrowValue) ||
        _putenv_s(narrowName.c_str(), narrowValue.c_str()) ||
        !::SetEnvironmentVariableW(name.c_str(), value.c_str())) {
      return false;
    }
  }
  return true;
}

/**
 * At this point the child process has been created in a suspended state. Any
 * additional startup work (eg, blocklist setup) should go here.
 *
 * @return Ok if browser startup should proceed
 */
static mozilla::LauncherVoidResult PostCreationSetup(
    const wchar_t* aFullImagePath, HANDLE aChildProcess,
    HANDLE aChildMainThread, mozilla::DeelevationStatus aDStatus,
    const bool aIsSafeMode, const bool aDisableDynamicBlocklist,
    mozilla::Maybe<std::wstring> aBlocklistFileName) {
  /* scope for txManager */ {
    mozilla::nt::CrossExecTransferManager txManager(aChildProcess);
    if (!txManager) {
      return LAUNCHER_ERROR_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
    }

    using mozilla::gDeelevationStatus;

    void* targetAddress = (LPVOID)&gDeelevationStatus;

    auto const guard = txManager.Protect(
        targetAddress, sizeof(gDeelevationStatus), PAGE_READWRITE);

    mozilla::LauncherVoidResult result =
        txManager.Transfer(targetAddress, &aDStatus, sizeof(aDStatus));
    if (result.isErr()) {
      return result;
    }

    using mozilla::DenBrowserLaunchAuthorization;
    using mozilla::gDenBrowserLaunchAuthorization;
    targetAddress = (LPVOID)&gDenBrowserLaunchAuthorization;
    auto const authorizationGuard = txManager.Protect(
        targetAddress, sizeof(gDenBrowserLaunchAuthorization), PAGE_READWRITE);
    const DenBrowserLaunchAuthorization authorization =
        DenBrowserLaunchAuthorization::AuthorizedBrowser;
    result = txManager.Transfer(targetAddress, &authorization,
                                sizeof(authorization));
    if (result.isErr()) {
      return result;
    }
  }

  return mozilla::InitializeDllBlocklistOOPFromLauncher(
      aFullImagePath, aChildProcess, aDisableDynamicBlocklist,
      aBlocklistFileName);
}

/**
 * Create a new Job object and assign |aProcess| to it.  If something fails
 * in this function, we return nullptr but continue without recording
 * a launcher failure because it's not a critical problem to launch
 * the browser process.
 */
static nsReturnRef<HANDLE> CreateJobAndAssignProcess(HANDLE aProcess) {
  nsAutoHandle empty;
  nsAutoHandle job(::CreateJobObjectW(nullptr, nullptr));

  // Set JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK to put only browser process
  // into a job without putting children of browser process into the job.
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = {};
  jobInfo.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
  if (!::SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                 &jobInfo, sizeof(jobInfo))) {
    return empty.out();
  }

  if (!::AssignProcessToJobObject(job.get(), aProcess)) {
    return empty.out();
  }

  return job.out();
}

enum class VCRuntimeDLLDir : bool {
  Application,
  System,
};

/* Returns true and sets aOutVersion to Nothing() if msvcp140.dll does not
 * exist in aDir. Returns true and sets aOutVersion to Some(version) if the
 * file exists and we successfully extract the version info. Returns false on
 * failure paths that prevent us from reaching any conclusion.
 */
static bool GetMSVCP140VersionInfo(VCRuntimeDLLDir aDir,
                                   mozilla::Maybe<uint64_t>& aOutVersion) {
  wchar_t dllPath[MAX_PATH];
  if (aDir == VCRuntimeDLLDir::Application) {
    DWORD size = ::GetModuleFileNameW(nullptr, dllPath, MAX_PATH);
    if (!size ||
        (size == MAX_PATH && ::GetLastError() == ERROR_INSUFFICIENT_BUFFER) ||
        !::PathRemoveFileSpecW(dllPath)) {
      return false;
    }
  } else {
    MOZ_ASSERT(aDir == VCRuntimeDLLDir::System);
    UINT size = ::GetSystemDirectoryW(dllPath, MAX_PATH);
    if (!size || size >= MAX_PATH) {
      return false;
    }
  }

  if (!::PathAppendW(dllPath, L"msvcp140.dll")) {
    return false;
  }
  HMODULE crt =
      ::LoadLibraryExW(dllPath, nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  if (!crt) {
    if (::GetLastError() != ERROR_FILE_NOT_FOUND) {
      return false;
    }
    aOutVersion.reset();
    return true;
  }

  mozilla::nt::PEHeaders headers{crt};
  uint64_t outVersion;
  bool result = headers.GetVersionInfo(outVersion);
  if (result) {
    aOutVersion.emplace(outVersion);
  }

  ::FreeLibrary(crt);
  return result;
}

/**
 * Choose whether we want to favor loading DLLs from the system directory over
 * the application directory. This choice automatically propagates to all child
 * processes. In particular, it determines whether child processes will load
 * Visual C++ runtime DLLs from the system or the application directory at
 * startup.
 *
 * Whenever possible, we want all processes to favor loading DLLs from the
 * system directory. But if old Visual C++ runtime DLLs are installed
 * system-wide, then we must favor loading from the application directory
 * instead to ensure compatibility, at least during startup. So in this case we
 * only apply the delayed variant of the mitigation and only in sandboxed
 * processes, which is the best compromise (see SandboxBroker::LaunchApp).
 *
 * This function is called from the launcher process *and* the browser process.
 * This is because if the launcher process is disabled, we still want the
 * browser process to go through this code so that it enforces the correct
 * choice for itself and for child processes.
 */
static void EnablePreferLoadFromSystem32IfCompatible() {
  // We may already have the mitigation if we are the browser process and we
  // inherited it from the launcher process.
  if (!mozilla::IsPreferLoadFromSystem32Available() ||
      mozilla::IsPreferLoadFromSystem32Enabled()) {
    return;
  }

  mozilla::Maybe<uint64_t> systemDirVersion;
  if (!GetMSVCP140VersionInfo(VCRuntimeDLLDir::System, systemDirVersion)) {
    return;
  }

  bool isCompatible = false;
  if (systemDirVersion.isNothing()) {
    // No system-wide runtime DLLs: we won't run into a conflict
    isCompatible = true;
  } else {
    mozilla::Maybe<uint64_t> appDirVersion;
    if (GetMSVCP140VersionInfo(VCRuntimeDLLDir::Application, appDirVersion) &&
        appDirVersion.isSome() && *systemDirVersion >= *appDirVersion) {
      // The system-wide runtime DLLs are at least as recent as ours
      isCompatible = true;
    }
  }

  if (isCompatible) {
    mozilla::DebugOnly<bool> setOk = mozilla::EnablePreferLoadFromSystem32();
    MOZ_ASSERT(setOk);
  }
}

/**
 * Any mitigation policies that should be set on the browser process should go
 * here.
 */
static void SetMitigationPolicies(mozilla::ProcThreadAttributes& aAttrs,
                                  const bool aIsSafeMode) {
  // Note: Do *not* handle IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON here. For this
  //       mitigation we rely on EnablePreferLoadFromSystem32IfCompatible().
  //       The launcher process or the browser process will choose whether we
  //       want to apply the mitigation or not, and child processes will
  //       automatically inherit that choice.

#if defined(_M_ARM64)
  // Disable CFG on older versions of ARM64 Windows to avoid a crash in COM.
  if (!mozilla::IsWin10Sep2018UpdateOrLater()) {
    aAttrs.AddMitigationPolicy(
        PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF);
  }
#endif  // defined(_M_ARM64)
}

static mozilla::LauncherFlags ProcessCmdLine(int&, wchar_t*[]) {
  // DenBrowser's public grammar contains no launcher-control switches. In
  // particular, callers cannot request headless/debug automation, handle
  // inheritance, waiting, or suppression of de-elevation.
  return mozilla::LauncherFlags::eNone;
}

static void MaybeBreakForBrowserDebugging() {
  if (mozilla::EnvHasValue("MOZ_DEBUG_BROWSER_PROCESS")) {
    ::DebugBreak();
    return;
  }

  const wchar_t* pauseLenS = _wgetenv(L"MOZ_DEBUG_BROWSER_PAUSE");
  if (!pauseLenS || !(*pauseLenS)) {
    return;
  }

  DWORD pauseLenMs = wcstoul(pauseLenS, nullptr, 10) * 1000;
  printf_stderr("\n\nBROWSERBROWSERBROWSERBROWSER\n  debug me @ %lu\n\n",
                ::GetCurrentProcessId());
  ::Sleep(pauseLenMs);
}

static bool DoLauncherProcessChecks(int& argc, wchar_t** argv) {
  // NB: We run all tests in this function instead of returning early in order
  // to ensure that all side effects take place, such as clearing environment
  // variables.
  bool result = false;

#if defined(MOZ_LAUNCHER_PROCESS)
  // We still prefer to compare file ids.  Comparing NT paths i.e. passing
  // CompareNtPathsOnly to IsSameBinaryAsParentProcess is much faster, but
  // we're not 100% sure that NT path comparison perfectly prevents the
  // launching loop of the launcher process.
  mozilla::LauncherResult<bool> isSame = mozilla::IsSameBinaryAsParentProcess();
  if (isSame.isOk()) {
    result = !isSame.unwrap();
  } else {
    HandleLauncherError(isSame.unwrapErr());
  }
#endif  // defined(MOZ_LAUNCHER_PROCESS)

  if (mozilla::EnvHasValue("MOZ_LAUNCHER_PROCESS")) {
    mozilla::SaveToEnv("MOZ_LAUNCHER_PROCESS=");
    result = true;
  }

  result |=
      mozilla::CheckArg(argc, argv, "launcher", nullptr,
                        mozilla::CheckArgFlag::RemoveArg) == mozilla::ARG_FOUND;

  return result;
}

#if defined(MOZ_LAUNCHER_PROCESS)
static mozilla::Maybe<bool> RunAsLauncherProcess(
    mozilla::LauncherRegistryInfo& aRegInfo, int& argc, wchar_t** argv) {
#else
static mozilla::Maybe<bool> RunAsLauncherProcess(int& argc, wchar_t** argv) {
#endif  // defined(MOZ_LAUNCHER_PROCESS)
  bool runAsLauncher = DoLauncherProcessChecks(argc, argv);

#if defined(MOZ_LAUNCHER_PROCESS)
  // DenBrowser must never let launcher crash telemetry or a registry override
  // demote a validated launcher request into an in-process browser start.
  bool forceLauncher = runAsLauncher;

  mozilla::LauncherRegistryInfo::ProcessType desiredType =
      runAsLauncher ? mozilla::LauncherRegistryInfo::ProcessType::Launcher
                    : mozilla::LauncherRegistryInfo::ProcessType::Browser;

  mozilla::LauncherRegistryInfo::CheckOption checkOption =
      forceLauncher ? mozilla::LauncherRegistryInfo::CheckOption::Force
                    : mozilla::LauncherRegistryInfo::CheckOption::Default;

  mozilla::LauncherResult<mozilla::LauncherRegistryInfo::ProcessType>
      runAsType = aRegInfo.Check(desiredType, checkOption);

  if (runAsType.isErr()) {
    mozilla::HandleLauncherError(runAsType);
    return mozilla::Nothing();
  }

  runAsLauncher = runAsType.unwrap() ==
                  mozilla::LauncherRegistryInfo::ProcessType::Launcher;
#endif  // defined(MOZ_LAUNCHER_PROCESS)

  if (!runAsLauncher) {
    // In this case, we will be proceeding to run as the browser.
    // We should check MOZ_DEBUG_BROWSER_* env vars.
    MaybeBreakForBrowserDebugging();
  }

  return mozilla::Some(runAsLauncher);
}

namespace mozilla {

Maybe<int> LauncherMain(int& argc, wchar_t* argv[]) {
  const bool authorizedBrowser =
      gDenBrowserLaunchAuthorization ==
      DenBrowserLaunchAuthorization::AuthorizedBrowser;
  const bool hasContentProcessFlag =
      denbrowser::HasContentProcessFlag(argc, argv);

  // A typed -contentproc flag is not authority. Genuine same-executable Gecko
  // children use one canonical flag at argv[1] and have the installed browser
  // as their actual parent. Anything else is rejected before launcher or
  // browser initialization can reinterpret it.
  if (hasContentProcessFlag) {
    if (authorizedBrowser ||
        !denbrowser::IsCanonicalContentProcessCommandLine(argc, argv)) {
      return Some(127);
    }
#if defined(MOZ_LAUNCHER_PROCESS)
    LauncherResult<bool> sameParent = IsSameBinaryAsParentProcess();
    if (sameParent.isErr()) {
      HandleLauncherError(sameParent.unwrapErr());
      return Some(127);
    }
    if (!sameParent.unwrap()) {
      return Some(127);
    }
#else
    return Some(127);
#endif
    EnsureBrowserCommandlineSafe(argc, argv);
    return Nothing();
  }

  if (!denbrowser::IsAllowedBrowserCommandLine(argc, argv)) {
    return Some(127);
  }

  EnsureBrowserCommandlineSafe(argc, argv);
  if (!SetArgv0ToFullBinaryPath(argv)) {
    HandleLauncherError(LAUNCHER_ERROR_GENERIC());
    return Some(127);
  }

  std::wstring applicationDirectory;
  if (!DenBrowserGetApplicationDirectory(argv[0], applicationDirectory)) {
    return Some(127);
  }

  DenBrowserEnvironment currentEnvironment;
  if (!DenBrowserBuildEnvironment(nullptr, applicationDirectory,
                                  currentEnvironment) ||
      !DenBrowserApplyCurrentEnvironment(currentEnvironment)) {
    return Some(127);
  }

  // Called from the launcher process *and* the browser process.
  EnablePreferLoadFromSystem32IfCompatible();

  if (authorizedBrowser) {
    return Nothing();
  }

  // The marker is created only after the public/restart grammar and caller
  // environment have been validated. It is consumed by the existing launcher
  // role selection below and is never copied into the browser environment.
  if (_putenv_s("MOZ_LAUNCHER_PROCESS", "1") ||
      !::SetEnvironmentVariableW(L"MOZ_LAUNCHER_PROCESS", L"1")) {
    return Some(127);
  }

#if defined(MOZ_LAUNCHER_PROCESS)
  LauncherRegistryInfo regInfo;
  Maybe<bool> runAsLauncher = RunAsLauncherProcess(regInfo, argc, argv);
  LauncherResult<std::wstring> blocklistFileNameResult =
      regInfo.GetBlocklistFileName();
  Maybe<std::wstring> blocklistFileName =
      blocklistFileNameResult.isOk() ? Some(blocklistFileNameResult.unwrap())
                                     : Nothing();
#else
  Maybe<bool> runAsLauncher = RunAsLauncherProcess(argc, argv);
  Maybe<std::wstring> blocklistFileName = Nothing();
#endif  // defined(MOZ_LAUNCHER_PROCESS)
  if (!runAsLauncher || !runAsLauncher.value()) {
    return Some(127);
  }

#if defined(MOZ_SANDBOX)
  // Ensure the relevant mitigations are enforced.
  mozilla::sandboxing::ApplyParentProcessMitigations();
#endif

  mozilla::UseParentConsole();

  LauncherFlags flags = ProcessCmdLine(argc, argv);

  nsAutoHandle mediumIlToken;
  LauncherResult<ElevationState> elevationState =
      GetElevationState(argv[0], flags, mediumIlToken);
  if (elevationState.isErr()) {
    HandleLauncherError(elevationState);
    return Some(127);
  }

  // Shell-based de-elevation cannot carry the launch authorization. A normal
  // user launch proceeds; a directly available medium-integrity token is used
  // when possible; otherwise an elevated launch fails closed.
  DeelevationStatus deelevationStatus = DeelevationStatus::Unknown;
  if (mediumIlToken.get()) {
    deelevationStatus = DeelevationStatus::PartiallyDeelevated;
  } else if (elevationState.unwrap() == ElevationState::eNormalUser) {
    deelevationStatus = DeelevationStatus::StartedUnprivileged;
  } else {
    HandleLauncherError(LAUNCHER_ERROR_FROM_WIN32(ERROR_ELEVATION_REQUIRED));
    return Some(127);
  }

#if defined(MOZ_LAUNCHER_PROCESS)
  // Update the registry as Launcher
  LauncherVoidResult commitResult = regInfo.Commit();
  if (commitResult.isErr()) {
    mozilla::HandleLauncherError(commitResult);
    return Some(127);
  }
#endif  // defined(MOZ_LAUNCHER_PROCESS)

  // Now proceed with setting up the parameters for process creation
  UniquePtr<wchar_t[]> cmdLine(MakeCommandLine(argc, argv));
  if (!cmdLine) {
    HandleLauncherError(LAUNCHER_ERROR_GENERIC());
    return Some(127);
  }

  const Maybe<bool> isSafeMode =
      IsSafeModeRequested(argc, argv, SafeModeFlag::NoKeyPressCheck);
  if (!isSafeMode) {
    HandleLauncherError(LAUNCHER_ERROR_FROM_WIN32(ERROR_INVALID_PARAMETER));
    return Some(127);
  }

  ProcThreadAttributes attrs;
  SetMitigationPolicies(attrs, isSafeMode.value());

  DWORD creationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

  STARTUPINFOEXW siex;
  LauncherResult<bool> attrsOk = attrs.AssignTo(siex);
  if (attrsOk.isErr()) {
    HandleLauncherError(attrsOk);
    return Some(127);
  }

  if (attrsOk.unwrap()) {
    creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
  }

  // Pass on the path of the shortcut used to launch this process, if any.
  STARTUPINFOW currentStartupInfo = {.cb = sizeof(STARTUPINFOW)};
  GetStartupInfoW(&currentStartupInfo);
  if ((currentStartupInfo.dwFlags & STARTF_TITLEISLINKNAME) &&
      currentStartupInfo.lpTitle) {
    siex.StartupInfo.dwFlags |= STARTF_TITLEISLINKNAME;
    siex.StartupInfo.lpTitle = currentStartupInfo.lpTitle;
  }

  PROCESS_INFORMATION pi = {};
  BOOL createOk;

  DenBrowserEnvironment browserEnvironment;
  if (!DenBrowserBuildEnvironment(mediumIlToken.get(), applicationDirectory,
                                  browserEnvironment)) {
    return Some(127);
  }
  UniquePtr<wchar_t[]> environmentBlock =
      DenBrowserSerializeEnvironment(browserEnvironment);
  if (!environmentBlock) {
    return Some(127);
  }

  mozilla::denbrowser::ProcessSecurityAttributes processSecurity;
  if (!processSecurity) {
    HandleLauncherError(LAUNCHER_ERROR_FROM_WIN32(processSecurity.LastError()));
    return Some(127);
  }

  if (mediumIlToken.get()) {
    createOk = ::CreateProcessAsUserW(
        mediumIlToken.get(), argv[0], cmdLine.get(), processSecurity.Get(),
        nullptr, FALSE, creationFlags, environmentBlock.get(),
        applicationDirectory.c_str(), &siex.StartupInfo, &pi);
  } else {
    createOk =
        ::CreateProcessW(argv[0], cmdLine.get(), processSecurity.Get(), nullptr,
                         FALSE, creationFlags, environmentBlock.get(),
                         applicationDirectory.c_str(), &siex.StartupInfo, &pi);
  }

  if (!createOk) {
    HandleLauncherError(LAUNCHER_ERROR_FROM_LAST());
    return Some(127);
  }

  nsAutoHandle process(pi.hProcess);
  nsAutoHandle mainThread(pi.hThread);

  nsAutoHandle job;
  if (flags & LauncherFlags::eWaitForBrowser) {
    job = CreateJobAndAssignProcess(process.get());
  }

  bool disableDynamicBlocklist = IsDynamicBlocklistDisabled(
      isSafeMode.value(),
      mozilla::CheckArg(
          argc, argv, mozilla::geckoargs::sDisableDynamicDllBlocklist.sMatch,
          nullptr, mozilla::CheckArgFlag::None) == mozilla::ARG_FOUND);
  LauncherVoidResult setupResult = PostCreationSetup(
      argv[0], process.get(), mainThread.get(), deelevationStatus,
      isSafeMode.value(), disableDynamicBlocklist, blocklistFileName);
  if (setupResult.isErr()) {
    HandleLauncherError(setupResult);
    ::TerminateProcess(process.get(), 1);
    return Some(127);
  }

  if (::ResumeThread(mainThread.get()) == static_cast<DWORD>(-1)) {
    HandleLauncherError(LAUNCHER_ERROR_FROM_LAST());
    ::TerminateProcess(process.get(), 1);
    return Some(127);
  }

  if (flags & LauncherFlags::eWaitForBrowser) {
    DWORD exitCode;
    if (::WaitForSingleObject(process.get(), INFINITE) == WAIT_OBJECT_0 &&
        ::GetExitCodeProcess(process.get(), &exitCode)) {
      // Propagate the browser process's exit code as our exit code.
      return Some(static_cast<int>(exitCode));
    }
  } else {
    const DWORD timeout =
        ::IsDebuggerPresent() ? INFINITE : kWaitForInputIdleTimeoutMS;

    // Keep the current process around until the callback process has created
    // its message queue, to avoid the launched process's windows being forced
    // into the background.
    mozilla::WaitForInputIdle(process.get(), timeout);
  }

  return Some(0);
}

}  // namespace mozilla
