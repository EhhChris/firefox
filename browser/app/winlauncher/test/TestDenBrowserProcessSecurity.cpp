/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include <string>

#include "mozilla/DenBrowserProcessSecurity.h"

using mozilla::denbrowser::kDeniedProcessAccess;
using mozilla::denbrowser::ProcessSecurityAttributes;

static constexpr char kTestName[] = "DenBrowserProcessSecurity";

static int Fail(const char* aMessage, DWORD aError = ERROR_SUCCESS) {
  printf("TEST-FAILED | %s | %s", kTestName, aMessage);
  if (aError != ERROR_SUCCESS) {
    printf(" (error=%lu)", aError);
  }
  printf("\n");
  return 1;
}

static bool DisableDebugPrivilege() {
  HANDLE token = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
                          &token)) {
    return false;
  }

  LUID luid = {};
  if (!::LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
    ::CloseHandle(token);
    return false;
  }

  TOKEN_PRIVILEGES privileges = {};
  privileges.PrivilegeCount = 1;
  privileges.Privileges[0].Luid = luid;
  privileges.Privileges[0].Attributes = 0;
  ::SetLastError(ERROR_SUCCESS);
  BOOL adjusted =
      ::AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
  DWORD error = ::GetLastError();
  ::CloseHandle(token);
  return adjusted &&
         (error == ERROR_SUCCESS || error == ERROR_NOT_ALL_ASSIGNED);
}

static bool IsAceFor(ACE_HEADER* aHeader, WELL_KNOWN_SID_TYPE aSidType,
                     ACCESS_MASK aMask) {
  if (aHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
    auto* ace = reinterpret_cast<ACCESS_DENIED_ACE*>(aHeader);
    return ace->Mask == aMask && ::IsWellKnownSid(&ace->SidStart, aSidType);
  }
  if (aHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
    auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(aHeader);
    return ace->Mask == aMask && ::IsWellKnownSid(&ace->SidStart, aSidType);
  }
  return false;
}

static bool ValidateDescriptor(ProcessSecurityAttributes& aSecurity) {
  SECURITY_ATTRIBUTES* attributes = aSecurity.Get();
  if (!attributes || attributes->nLength != sizeof(SECURITY_ATTRIBUTES) ||
      attributes->bInheritHandle ||
      !::IsValidSecurityDescriptor(attributes->lpSecurityDescriptor)) {
    return false;
  }

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  if (!::GetSecurityDescriptorControl(attributes->lpSecurityDescriptor,
                                      &control, &revision) ||
      !(control & SE_DACL_PROTECTED)) {
    return false;
  }

  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  PACL dacl = nullptr;
  if (!::GetSecurityDescriptorDacl(attributes->lpSecurityDescriptor, &present,
                                   &dacl, &defaulted) ||
      !present || !dacl || dacl->AceCount != 3) {
    return false;
  }

  ACE_HEADER* denyOwner = nullptr;
  ACE_HEADER* allowSystem = nullptr;
  ACE_HEADER* allowOwner = nullptr;
  return ::GetAce(dacl, 0, reinterpret_cast<void**>(&denyOwner)) &&
         ::GetAce(dacl, 1, reinterpret_cast<void**>(&allowSystem)) &&
         ::GetAce(dacl, 2, reinterpret_cast<void**>(&allowOwner)) &&
         denyOwner->AceType == ACCESS_DENIED_ACE_TYPE &&
         IsAceFor(denyOwner, WinCreatorOwnerRightsSid, kDeniedProcessAccess) &&
         allowSystem->AceType == ACCESS_ALLOWED_ACE_TYPE &&
         IsAceFor(allowSystem, WinLocalSystemSid, GENERIC_ALL) &&
         allowOwner->AceType == ACCESS_ALLOWED_ACE_TYPE &&
         IsAceFor(allowOwner, WinCreatorOwnerRightsSid, GENERIC_ALL);
}

static bool ExpectOpen(DWORD aPid, ACCESS_MASK aAccess, bool aAllowed) {
  ::SetLastError(ERROR_SUCCESS);
  HANDLE process = ::OpenProcess(aAccess, FALSE, aPid);
  DWORD error = ::GetLastError();
  if (process) {
    ::CloseHandle(process);
  }
  return aAllowed ? process != nullptr
                  : process == nullptr && error == ERROR_ACCESS_DENIED;
}

static int ChildMain() {
  char source[] = "denbrowser";
  char destination[sizeof(source)] = {};
  SIZE_T read = 0;
  if (!::ReadProcessMemory(::GetCurrentProcess(), source, destination,
                           sizeof(source), &read) ||
      read != sizeof(source) || memcmp(source, destination, sizeof(source))) {
    return Fail("ReadProcessMemory failed for the self pseudohandle",
                ::GetLastError());
  }

  void* allocation = ::VirtualAllocEx(::GetCurrentProcess(), nullptr, 4096,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!allocation) {
    return Fail("VirtualAllocEx failed for the self pseudohandle",
                ::GetLastError());
  }
  if (!::VirtualFreeEx(::GetCurrentProcess(), allocation, 0, MEM_RELEASE)) {
    return Fail("VirtualFreeEx failed for the self pseudohandle",
                ::GetLastError());
  }

  HANDLE event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
  HANDLE duplicate = nullptr;
  if (!event ||
      !::DuplicateHandle(::GetCurrentProcess(), event, ::GetCurrentProcess(),
                         &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
    DWORD error = ::GetLastError();
    if (event) {
      ::CloseHandle(event);
    }
    return Fail("DuplicateHandle failed for the self pseudohandle", error);
  }
  ::CloseHandle(duplicate);
  ::CloseHandle(event);

  if (!ExpectOpen(::GetCurrentProcessId(), PROCESS_VM_READ, false)) {
    return Fail("A real self reopen unexpectedly obtained PROCESS_VM_READ");
  }
  return 0;
}

static int ParentMain(const wchar_t* aExecutable) {
  if (!DisableDebugPrivilege()) {
    return Fail("Could not disable SeDebugPrivilege", ::GetLastError());
  }

  ProcessSecurityAttributes security;
  if (!security) {
    return Fail("Could not construct process security attributes",
                security.LastError());
  }
  if (!ValidateDescriptor(security)) {
    return Fail("Process security descriptor did not match the policy");
  }

  std::wstring commandLine = L"\"";
  commandLine += aExecutable;
  commandLine += L"\" --child";
  STARTUPINFOW startup = {sizeof(startup)};
  PROCESS_INFORMATION process = {};
  if (!::CreateProcessW(aExecutable, commandLine.data(), security.Get(),
                        nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr,
                        &startup, &process)) {
    return Fail("CreateProcessW failed", ::GetLastError());
  }

  int result = 0;
  const ACCESS_MASK allowed[] = {
      PROCESS_QUERY_LIMITED_INFORMATION,
      PROCESS_QUERY_INFORMATION,
      PROCESS_CREATE_THREAD,
      PROCESS_CREATE_PROCESS,
      PROCESS_DUP_HANDLE,
      PROCESS_VM_OPERATION,
      PROCESS_VM_WRITE,
      SYNCHRONIZE,
      PROCESS_TERMINATE,
  };
  for (ACCESS_MASK access : allowed) {
    if (!ExpectOpen(process.dwProcessId, access, true)) {
      result = Fail("An allowed process open failed", ::GetLastError());
      break;
    }
  }

  const ACCESS_MASK denied[] = {PROCESS_VM_READ, WRITE_DAC, WRITE_OWNER,
                                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                PROCESS_ALL_ACCESS};
  if (!result) {
    for (ACCESS_MASK access : denied) {
      if (!ExpectOpen(process.dwProcessId, access, false)) {
        result = Fail("A denied process open unexpectedly succeeded");
        break;
      }
    }
  }

  if (!result && ::ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    result = Fail("ResumeThread failed", ::GetLastError());
  }
  if (!result &&
      ::WaitForSingleObject(process.hProcess, 30000) != WAIT_OBJECT_0) {
    result = Fail("Timed out waiting for the child", ::GetLastError());
  }

  DWORD exitCode = 1;
  if (!result &&
      (!::GetExitCodeProcess(process.hProcess, &exitCode) || exitCode != 0)) {
    result = Fail("The child self-access checks failed", exitCode);
  }

  if (result) {
    ::TerminateProcess(process.hProcess, 1);
  }
  ::CloseHandle(process.hThread);
  ::CloseHandle(process.hProcess);
  return result;
}

extern "C" int wmain(int argc, wchar_t* argv[]) {
  if (argc == 2 && !wcscmp(argv[1], L"--child")) {
    return ChildMain();
  }
  if (argc != 1) {
    return Fail("Unexpected command line");
  }
  return ParentMain(argv[0]);
}
