/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifndef mozilla_DenBrowserProcessSecurity_h
#define mozilla_DenBrowserProcessSecurity_h

#include <windows.h>

#include "mozilla/Types.h"

namespace mozilla::denbrowser {

// PROCESS_DUP_HANDLE must remain available to Firefox's broker IPC channels.
// Denying PROCESS_VM_READ still blocks the access required by an external
// MiniDumpWriteDump call, while the standard rights prevent the owner from
// replacing this protected DACL.
constexpr ACCESS_MASK kDeniedProcessAccess =
    PROCESS_VM_READ | WRITE_DAC | WRITE_OWNER;

class MFBT_API ProcessSecurityAttributes final {
 public:
  ProcessSecurityAttributes();
  ~ProcessSecurityAttributes();

  explicit operator bool() const { return mDescriptor != nullptr; }
  DWORD LastError() const { return mLastError; }
  SECURITY_ATTRIBUTES* Get() { return mDescriptor ? &mAttributes : nullptr; }

  ProcessSecurityAttributes(const ProcessSecurityAttributes&) = delete;
  ProcessSecurityAttributes& operator=(const ProcessSecurityAttributes&) =
      delete;

 private:
  PSECURITY_DESCRIPTOR mDescriptor = nullptr;
  SECURITY_ATTRIBUTES mAttributes = {};
  DWORD mLastError = ERROR_SUCCESS;
};

}  // namespace mozilla::denbrowser

#endif  // mozilla_DenBrowserProcessSecurity_h
