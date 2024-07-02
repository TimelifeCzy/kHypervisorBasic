#include "shadow_hook.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/util.h"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include "list.h"
#include "hook.h"

// Copy of a page seen by a guest as a result of memory shadowing
struct Page {
  UCHAR* page;  // A page aligned copy of a page
};

// Contains a single steal hook information
struct HookInformation {
  void* patch_address;  // An address where a hook is installed
  void* handler;        // An address of the handler routine

  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
  // is exposed to a guest for read and write operation against the page of
  // patch_address, and shadow_page_base_for_exec is exposed for execution.
  Page* shadow_page_base_for_rw;
  Page* shadow_page_base_for_exec;

  // Physical address of the above two copied pages
  ULONG64 pa_base_for_rw;
  ULONG64 pa_base_for_exec;
};

// Data structure shared across all processors
struct SharedShadowHookData {
  LIST_ELEM list;
  HookInformation* hooks;
};

// A structure reflects inline hook code.
#include <pshpack1.h>
#if defined(_AMD64_)
struct TrampolineCode {
  UCHAR nop;
  UCHAR jmp[6];
  void* address;
};
static_assert(sizeof(TrampolineCode) == 15, "Size check");
#else

struct TrampolineCode {
  UCHAR nop;
  UCHAR push;
  void* address;
  UCHAR ret;
};
static_assert(sizeof(TrampolineCode) == 7, "Size check");

#endif
#include <poppack.h>

// Returns code bytes for inline hooking
_Use_decl_annotations_ EXTERN_C static TrampolineCode ShpMakeTrampolineCode(
    void* hook_handler
) 
{
  PAGED_CODE();

#if defined(_AMD64_)
  // 90               nop
  // ff2500000000     jmp     qword ptr cs:jmp_addr
  // jmp_addr:
  // 0000000000000000 dq 0
  return {
      0x90,
      {
          0xff,
          0x25,
          0x00,
          0x00,
          0x00,
          0x00,
      },
      hook_handler,
  };
#else
  // 90               nop
  // 6832e30582       push    offset nt!ExFreePoolWithTag + 0x2 (8205e332)
  // c3               ret
  return {
      0x90,
      0x68,
      hook_handler,
      0xc3,
  };
#endif
}

// RW Epage
// sys_functionaddr
// hook_functionaddr
_Use_decl_annotations_ extern "C" bool ShInstallHook(
    SharedShadowHookData* shared_sh_data, void* address,
    ShadowHookTarget* target) {
  // create hook information
  HookInformation* info = (HookInformation*)ExAllocatePoolWithTag(
      NonPagedPool, sizeof(HookInformation), 'Tag');
  RtlSecureZeroMemory(info, sizeof(HookInformation));

  HookInformation* reusable_info = nullptr;
  // find sys_functionaddress to SharedShadowHookData
  SharedShadowHookData* shaobj =
      (SharedShadowHookData*)List_Head(shared_sh_data);
  while (shaobj) {
    if (shaobj->hooks->patch_address == address) {
      reusable_info = shaobj->hooks;
      break;
    }
    shaobj = (SharedShadowHookData*)List_Next(shared_sh_data);
  }

  // find Success && save old rw exec attr
  if (reusable_info) {
    info->shadow_page_base_for_rw = reusable_info->shadow_page_base_for_rw;
    info->shadow_page_base_for_exec = reusable_info->shadow_page_base_for_exec;
  } else {
    Page* page =
        (Page*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Page), 'Tag');
    Page* page1 =
        (Page*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Page), 'Tag');
    RtlSecureZeroMemory(page, sizeof(Page));
    RtlSecureZeroMemory(page1, sizeof(Page));
    info->shadow_page_base_for_rw = page;
    info->shadow_page_base_for_exec = page1;
    auto page_base = PAGE_ALIGN(address);
    RtlCopyMemory(info->shadow_page_base_for_rw->page, page_base, PAGE_SIZE);
    RtlCopyMemory(info->shadow_page_base_for_exec->page, page_base, PAGE_SIZE);
  }
  info->patch_address = address;
  info->pa_base_for_rw = UtilPaFromVa(info->shadow_page_base_for_rw->page);
  info->pa_base_for_exec = UtilPaFromVa(info->shadow_page_base_for_exec->page);
  info->handler = target->handler;

  // analys hook pointer
  //SIZE_T patch_size = 0; 
  //Hook_Tramp_CountBytes();
  //if (!patch_size) {
  //  return false;
  //} 
  return true;
}