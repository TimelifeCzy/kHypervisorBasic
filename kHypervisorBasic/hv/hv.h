#pragma once

#include <fltKernel.h>

extern "C" {

enum HvComponentFlags : ULONG {
  kHvComponentVmx = 0x00000001,
  kHvComponentEpt = 0x00000002,
  kHvComponentNestedVmx = 0x00000004,
  kHvComponentHooks = 0x00000008,
};

struct HvRuntimeConfig {
  ULONG component_flags;
};

typedef NTSTATUS (*HvModuleInitialize)(_In_ const HvRuntimeConfig* config);
typedef void (*HvModuleTerminate)();

struct HvModule {
  ULONG id;
  const char* name;
  HvModuleInitialize initialize;
  HvModuleTerminate terminate;
};

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
HvRegisterModule(_In_ const HvModule* module);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
HvInitialize(_In_opt_ const HvRuntimeConfig* config);

_IRQL_requires_max_(PASSIVE_LEVEL) void HvTerminate();

}  // extern "C"
