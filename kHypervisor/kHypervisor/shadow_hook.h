#pragma once
#include <fltKernel.h>
// Expresses where to install hooks by a function name, and its handlers
struct ShadowHookTarget {
  UNICODE_STRING target_name;  // An export name to hook
  void* handler;               // An address of a hook handler

  // An address of a trampoline code to call original function. Initialized by
  // a successful call of ShInstallHook().
  void* original_call;
};