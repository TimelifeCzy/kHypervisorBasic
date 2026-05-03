#include "hv.h"

#include "../vm.h"

extern "C" {

static const ULONG kHvMaxModules = 8;
static volatile LONG g_hv_initialized = FALSE;
static const HvModule* g_hv_modules[kHvMaxModules] = {};
static ULONG g_hv_module_count = 0;
static ULONG g_hv_initialized_module_count = 0;

_Use_decl_annotations_ NTSTATUS HvRegisterModule(const HvModule* module) {
  PAGED_CODE();

  if (!module || !module->initialize || !module->terminate) {
    return STATUS_INVALID_PARAMETER;
  }
  if (g_hv_initialized) {
    return STATUS_DEVICE_BUSY;
  }
  if (g_hv_module_count >= kHvMaxModules) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  for (ULONG i = 0; i < g_hv_module_count; ++i) {
    if (g_hv_modules[i]->id == module->id) {
      return STATUS_OBJECT_NAME_COLLISION;
    }
  }

  g_hv_modules[g_hv_module_count++] = module;
  return STATUS_SUCCESS;
}

static NTSTATUS HvpInitializeModules(const HvRuntimeConfig* config) {
  PAGED_CODE();

  g_hv_initialized_module_count = 0;
  for (ULONG i = 0; i < g_hv_module_count; ++i) {
    const auto module = g_hv_modules[i];
    const auto status = module->initialize(config);
    if (!NT_SUCCESS(status)) {
      while (g_hv_initialized_module_count) {
        const auto initialized_module =
            g_hv_modules[--g_hv_initialized_module_count];
        initialized_module->terminate();
      }
      return status;
    }
    ++g_hv_initialized_module_count;
  }
  return STATUS_SUCCESS;
}

static void HvpTerminateModules() {
  PAGED_CODE();

  while (g_hv_initialized_module_count) {
    const auto module = g_hv_modules[--g_hv_initialized_module_count];
    module->terminate();
  }
}

_Use_decl_annotations_ NTSTATUS HvInitialize(const HvRuntimeConfig* config) {
  PAGED_CODE();

  const auto flags =
      config ? config->component_flags : (kHvComponentVmx | kHvComponentEpt);
  if (!(flags & kHvComponentVmx) || !(flags & kHvComponentEpt)) {
    return STATUS_INVALID_PARAMETER;
  }

  if (InterlockedCompareExchange(&g_hv_initialized, TRUE, FALSE) != FALSE) {
    return STATUS_DEVICE_ALREADY_ATTACHED;
  }

  const auto status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    InterlockedExchange(&g_hv_initialized, FALSE);
    return status;
  }

  const HvRuntimeConfig default_config = {
      kHvComponentVmx | kHvComponentEpt};
  const auto active_config = config ? config : &default_config;
  const auto module_status = HvpInitializeModules(active_config);
  if (!NT_SUCCESS(module_status)) {
    VmTermination();
    InterlockedExchange(&g_hv_initialized, FALSE);
    return module_status;
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_ void HvTerminate() {
  PAGED_CODE();

  if (InterlockedCompareExchange(&g_hv_initialized, FALSE, TRUE) != TRUE) {
    return;
  }
  HvpTerminateModules();
  VmTermination();
}

}  // extern "C"
