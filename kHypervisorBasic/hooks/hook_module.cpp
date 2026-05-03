#include "hook_module.h"

#include "../hv/hv.h"
#include "../log.h"

extern "C" {

static const ULONG kHookModuleId = 'kcoH';
static volatile LONG g_hook_module_initialized = FALSE;
static HookModuleConfig g_hook_config = {};

static NTSTATUS HookpInitialize(const HvRuntimeConfig* config) {
  PAGED_CODE();

  if (!config || !(config->component_flags & kHvComponentHooks)) {
    return STATUS_SUCCESS;
  }
  if (InterlockedCompareExchange(&g_hook_module_initialized, TRUE, FALSE) !=
      FALSE) {
    return STATUS_SUCCESS;
  }

  g_hook_config.provider_flags = 0;
  HYPERPLATFORM_LOG_INFO("Hook module initialized.");
  return STATUS_SUCCESS;
}

static void HookpTerminate() {
  PAGED_CODE();

  if (InterlockedCompareExchange(&g_hook_module_initialized, FALSE, TRUE) !=
      TRUE) {
    return;
  }

  g_hook_config.provider_flags = 0;
  HYPERPLATFORM_LOG_INFO("Hook module terminated.");
}

static const HvModule g_hook_module = {
    kHookModuleId,
    "hook",
    HookpInitialize,
    HookpTerminate,
};

_Use_decl_annotations_ NTSTATUS HookModuleRegister() {
  PAGED_CODE();
  return HvRegisterModule(&g_hook_module);
}

}  // extern "C"
