#pragma once

#include <fltKernel.h>

extern "C" {

enum HookProviderFlags : ULONG {
  kHookProviderMsr = 0x00000001,
  kHookProviderEpt = 0x00000002,
};

struct HookModuleConfig {
  ULONG provider_flags;
};

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HookModuleRegister();

}  // extern "C"
