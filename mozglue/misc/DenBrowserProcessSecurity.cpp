/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "mozilla/DenBrowserProcessSecurity.h"

#include <sddl.h>

namespace {

constexpr wchar_t kProcessSecuritySddl[] =
    L"D:P(D;;0x000C0010;;;OW)(A;;GA;;;SY)(A;;GA;;;OW)";

static_assert(mozilla::denbrowser::kDeniedProcessAccess == 0x000C0010);

}  // namespace

namespace mozilla::denbrowser {

ProcessSecurityAttributes::ProcessSecurityAttributes() {
  if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kProcessSecuritySddl, SDDL_REVISION_1, &mDescriptor, nullptr)) {
    mLastError = ::GetLastError();
    return;
  }

  if (!::IsValidSecurityDescriptor(mDescriptor)) {
    mLastError = ERROR_INVALID_SECURITY_DESCR;
    ::LocalFree(mDescriptor);
    mDescriptor = nullptr;
    return;
  }

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  if (!::GetSecurityDescriptorControl(mDescriptor, &control, &revision)) {
    mLastError = ::GetLastError();
    ::LocalFree(mDescriptor);
    mDescriptor = nullptr;
    return;
  }
  if (!(control & SE_DACL_PROTECTED)) {
    mLastError = ERROR_INVALID_SECURITY_DESCR;
    ::LocalFree(mDescriptor);
    mDescriptor = nullptr;
    return;
  }

  mAttributes.nLength = sizeof(mAttributes);
  mAttributes.lpSecurityDescriptor = mDescriptor;
  mAttributes.bInheritHandle = FALSE;
}

ProcessSecurityAttributes::~ProcessSecurityAttributes() {
  if (mDescriptor) {
    ::LocalFree(mDescriptor);
  }
}

}  // namespace mozilla::denbrowser
