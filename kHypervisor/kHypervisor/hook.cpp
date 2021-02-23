#include "hook.h"
#include "../HyperPlatform/asm.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/log.h"
#include "PE.h"
#include "Common.h"
#include "Filehook.h"
#include <intrin.h>

#define MAX_SYSCALL_INDEX 0x1000

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

static ULONG64 close_count = 0;

enum SystemInformationClass {
  kSystemProcessInformation = 5,
};

// For NtQuerySystemInformation
typedef struct SystemProcessInformation {
  ULONG next_entry_offset;
  ULONG number_of_threads;
  LARGE_INTEGER working_set_private_size;
  ULONG hard_fault_count;
  ULONG number_of_threads_high_watermark;
  ULONG64 cycle_time;
  LARGE_INTEGER create_time;
  LARGE_INTEGER user_time;
  LARGE_INTEGER kernel_time;
  UNICODE_STRING image_name;
  // omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
} SystemProcessInformationNode;

/*
	Asm ------- g_Data
*/
extern "C" {
	CHAR HookEnabled[MAX_SYSCALL_INDEX] = {0};
	CHAR ArgTble[MAX_SYSCALL_INDEX] = {0};
	PVOID HookTable[MAX_SYSCALL_INDEX] = {0};

	ULONG64 KiSystemCall64Ptr = 0;    // Original LSTAR value
	ULONG64 KiServiceCopyEndPtr = 0;  // KiSystemServiceCopyEnd address
	ULONG64 KiSystemServiceRepeatPtr = 0;
	ULONG64 KiSaveDebugRegisterState = 0;
	ULONG64 KiUmsCallEntry = 0;
	ULONG64 KeServiceDescriptorTablePtr = 0;
	//
	// Import asm MyKiSysCall64
	//
	VOID SyscallEntryPoint();
}

//=======================================================
// Hook Asm analys ret number
//=======================================================
//---------------------------------------------------------------------------
// Hook_Analyze
//---------------------------------------------------------------------------
BOOLEAN Hook_Tramp_CountBytes(void* SysProc, ULONG* ByteCount,
                                BOOLEAN is64, BOOLEAN probe) {
    UCHAR* addr = (UCHAR*)SysProc;
    ULONG needlen =
        (is64 == 9 ? 13 : (is64 ? 12 : (File_TrusteerLoaded() ? 6 : 5)));
    ULONG copylen = 0;

    // count at least the (needlen) bytes of instructions from the
    // original entry point to our stub, as we will overwrite that area
    // later

    while (1) {
    HOOK_INST inst;
    BOOLEAN ok = Hook_Analyze(addr, probe, is64, &inst);
    if (!ok) return FALSE;

    if (inst.op1 == 0xFF && inst.op2 == 0x25 &&
        *(ULONG*)&addr[2] == 0) {
        // jmp dword/qword ptr [+00], so skip the following ULONG_PTR
        inst.len += sizeof(ULONG_PTR);
    }

    copylen += inst.len;
    if (copylen >= needlen) break;

    addr += inst.len;
    }

    *ByteCount = copylen;
    return TRUE;
}
//=======================================================
// Msr Hook Dpc
//=======================================================
VOID SHpUnMsrHookCallbackDPC(
	PRKDPC Dpc, 
	PVOID Context, 
	PVOID SystemArgument1,              
	PVOID SystemArgument2
) 
{
  UNREFERENCED_PARAMETER(Dpc);

  // 触发vm_exit_hook
  HYPERPLATFORM_LOG_INFO("Entry UtilVmCall disable Unmsrhook\r\n");

  UtilVmCall(HypercallNumber::KUnHookMsr, SyscallEntryPoint);

  HYPERPLATFORM_LOG_INFO("Exit UtilVmCall disable Unmsrhook\r\n");

  KeSignalCallDpcSynchronize(SystemArgument2);
  KeSignalCallDpcDone(SystemArgument1);
}

VOID SHpMsrHookCallbackDPC(
	PRKDPC Dpc, 
	PVOID Context, 
	PVOID SystemArgument1,
	PVOID SystemArgument2
) 
{
  UNREFERENCED_PARAMETER(Dpc);

  // 触发vm_exit_hook
  HYPERPLATFORM_LOG_INFO("Entry UtilVmCall enable Msr_hook\r\n");

  UtilVmCall(HypercallNumber::kHookMsr, SyscallEntryPoint);

  HYPERPLATFORM_LOG_INFO("Exit UtilVmCall enable Msr_hook\r\n");

  KeSignalCallDpcSynchronize(SystemArgument2);
  KeSignalCallDpcDone(SystemArgument1);
}

//=======================================================
// Get NtosBase && Ssdt Base
//=======================================================
NTSTATUS UtilSearchPattern(
	IN PCUCHAR pattern, IN UCHAR wildcard,       
	IN ULONG_PTR len, IN const VOID* base,                  
	IN ULONG_PTR size, OUT PVOID* ppFound
) {
  NT_ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
  if (ppFound == NULL || pattern == NULL || base == NULL)
    return STATUS_INVALID_PARAMETER;

  __try {
    for (ULONG_PTR i = 0; i < size - len; i++) {
      BOOLEAN found = TRUE;
      for (ULONG_PTR j = 0; j < len; j++) {
        if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
          found = FALSE;
          break;
        }
      }

      if (found != FALSE) {
        *ppFound = (PUCHAR)base + i;
        return STATUS_SUCCESS;
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_UNHANDLED_EXCEPTION;
  }

  return STATUS_NOT_FOUND;
}

PVOID UtilKernelBase(
	OUT PULONG pSize
) {
  NTSTATUS status = STATUS_SUCCESS;
  ULONG bytes = 0;
  PRTL_PROCESS_MODULES pMods = NULL;
  PVOID checkPtr = NULL;
  UNICODE_STRING routineName;

  // Already found
  if (g_KernelBase != NULL) {
    if (pSize) *pSize = g_KernelSize;
    return g_KernelBase;
  }

  RtlInitUnicodeString(&routineName, L"NtOpenFile");

  checkPtr = MmGetSystemRoutineAddress(&routineName);
  if (checkPtr == NULL) return NULL;

  // Protect from UserMode AV
  __try {
    status =
        ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) {
      DPRINT("BlackBone: %s: Invalid SystemModuleInformation size\n", CPU_IDX,
             __FUNCTION__);
      return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx, bytes,
                                                        HB_POOL_TAG);
    RtlZeroMemory(pMods, bytes);

    status =
        ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status)) {
      PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

      for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
        // System routine is inside module
        if (checkPtr >= pMod[i].ImageBase &&
            checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize)) {
          g_KernelBase = pMod[i].ImageBase;
          g_KernelSize = pMod[i].ImageSize;
          if (pSize) *pSize = g_KernelSize;
          break;
        }
      }
    }

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DPRINT("BlackBone: %s: Exception\n", CPU_IDX, __FUNCTION__);
  }

  if (pMods) ExFreePoolWithTag(pMods, HB_POOL_TAG);

  return g_KernelBase;
}

NTSTATUS UtilScanSection(
	IN PCCHAR section, IN PCUCHAR pattern,                    
	IN UCHAR wildcard, IN ULONG_PTR len,                   
	OUT PVOID* ppFound
) {
  NT_ASSERT(ppFound != NULL);
  if (ppFound == NULL) return STATUS_INVALID_PARAMETER;

  PVOID base = UtilKernelBase(NULL);
  if (!base) return STATUS_NOT_FOUND;

  PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
  if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

  PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
  for (PIMAGE_SECTION_HEADER pSection = pFirstSection;
       pSection < pFirstSection + pHdr->FileHeader.NumberOfSections;
       pSection++) {
    ANSI_STRING s1, s2;
    RtlInitAnsiString(&s1, section);
    RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
    if (RtlCompareString(&s1, &s2, TRUE) == 0)
      return UtilSearchPattern(pattern, wildcard, len,
                               (PUCHAR)base + pSection->VirtualAddress,
                               pSection->Misc.VirtualSize, ppFound);
  }

  return STATUS_NOT_FOUND;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE puGetSSdtBase(
)
{
  PUCHAR ntosBase = (PUCHAR)UtilKernelBase(NULL);

  // Already found
  if (g_SSDT != NULL) return g_SSDT;

  if (!ntosBase) return NULL;

  PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader(ntosBase);
  PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
  for (PIMAGE_SECTION_HEADER pSec = pFirstSec;
       pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++) {
    // Non-paged, non-discardable, readable sections
    // Probably still not fool-proof enough...
    if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
        pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
        !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
        (*(PULONG)pSec->Name != 'TINI') && (*(PULONG)pSec->Name != 'EGAP')) {
      PVOID pFound = NULL;

      // KiSystemServiceRepeat pattern
      UCHAR pattern[] =
          "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
      NTSTATUS status = UtilSearchPattern(pattern, 0xCC, sizeof(pattern) - 1,
                                          ntosBase + pSec->VirtualAddress,
                                          pSec->Misc.VirtualSize, &pFound);
      if (NT_SUCCESS(status)) {
        g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(
            (PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
        // DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n",
        // CPU_NUM, __FUNCTION__, g_SSDT );
        return g_SSDT;
      }
    }
  }

  return NULL;
}

PVOID PuGetSSDTEntry(
	IN ULONG index
) 
{
  ULONG size = 0;
  PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = puGetSSdtBase();
  PVOID pBase = UtilKernelBase(&size);

  if (pSSDT && pBase) {
    // Index range check
    if (index > pSSDT->NumberOfServices) return NULL;

    return (PUCHAR)pSSDT->ServiceTableBase +
           (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
  }

  return NULL;
}

ULONG64 InitalNothingFunction(
	const WCHAR* Name, 
	ULONG Offset
) {
  UNICODE_STRING unstrFunc;
  ULONG64 pCheckArea;
  RtlInitUnicodeString(&unstrFunc, Name);
  pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
  if (MmIsAddressValid((PVOID64)pCheckArea) && pCheckArea != NULL) {
    DbgPrint("InitalNothingFunction %p %ws \n", pCheckArea, Name);
    DbgPrint("Offset %p %ws \n", pCheckArea + Offset, Name);
    return (pCheckArea + Offset);
  }
  return 0;
}

//=======================================================
// Msr Hook
//=======================================================
/*
    fffff800`040c87ae 7550   jne nt!KiSystemServiceGdiTebAccess+0x49
    (fffff800`040c8800)
*/
UCHAR g_Signature[17] = {0x4d, 0x63, 0x1c, 0x82, 0x49, 0x8b, 0xc3, 0x49, 0xc1,
                         0xfb, 0x04, 0x4d, 0x03, 0xd3, 0x83, 0xff, 0x20};
ULONGLONG GetKiSystemServiceRepeat() {
  ULONG_PTR StartSearchAddress = (ULONG_PTR)__readmsr(0xC0000082);
  ULONG_PTR EndSearchAddress = StartSearchAddress + 0x500;
  ULONG_PTR i;
  ULONGLONG addr = 0;
  for (i = StartSearchAddress; i < EndSearchAddress; ++i) {
    if (*(PULONG_PTR)i == *(PULONG_PTR)g_Signature) {
      addr = i + 17;  //!!
      return addr;
    }
  }
  return 0;
}

NTSTATUS SHDestroyMsrHook() {
  NTSTATUS status = STATUS_SUCCESS;
  if (KiSystemCall64Ptr != 0) KeGenericCallDpc(SHpUnMsrHookCallbackDPC, NULL);
  if (NT_SUCCESS(status)) KiSystemCall64Ptr = 0;
  return status;
}

NTSTATUS SHRestoreMsrSyscall(
	IN ULONG index
) 
{
  if (index > MAX_SYSCALL_INDEX) return STATUS_INVALID_PARAMETER;

  KIRQL irql = KeGetCurrentIrql();
  if (irql < DISPATCH_LEVEL) irql = KeRaiseIrqlToDpcLevel();

  InterlockedExchange8(&HookEnabled[index], 0);
  InterlockedExchange8(&ArgTble[index], 0);
  InterlockedExchange64((PLONG64)&HookTable[index], 0);

  if (KeGetCurrentIrql() > irql) KeLowerIrql(irql);

  return STATUS_SUCCESS;
}

//	Msr Hook EntryPoint
NTSTATUS SHInitMsrHook(
	void* context
) {
  NTSTATUS status = STATUS_SUCCESS;

  KeServiceDescriptorTablePtr = (ULONG64)puGetSSdtBase();
  // InitSsdtBase
  if (!KeServiceDescriptorTablePtr) {
    DPRINT("HyperBone: CPU %d: %s: SSDT base not found\n", CPU_IDX,
           __FUNCTION__);
    return STATUS_NOT_FOUND;
  }

  // KiSystemServiceCopyEnd
  // F7 05 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 85 ? ? ? ? ? ? ? ? 41 FF D2
  if (KiServiceCopyEndPtr == 0) {
    CHAR pattern[] =
        "\xF7\x05\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x0F\x85\xcc\xcc\xcc\xcc\x41"
        "\xFF\xD2";
    status =
        UtilScanSection((PCCHAR) ".text", (PCUCHAR)pattern, 0xCC,
                        sizeof(pattern) - 1, (PVOID*)(&KiServiceCopyEndPtr));
    if (!NT_SUCCESS(status)) {
      DPRINT("HyperBone: CPU %d: %s: KiSystemServiceCopyEnd not found\n",
             CPU_IDX, __FUNCTION__);
      return status;
    }

    KiSystemServiceRepeatPtr = GetKiSystemServiceRepeat();
    if (!KiSystemServiceRepeatPtr) return STATUS_UNSUCCESSFUL;

    KiSaveDebugRegisterState =
        (ULONG64)InitalNothingFunction(L"KeBugCheckEx", 0x4b0);
    KiUmsCallEntry =
        (ULONG64)InitalNothingFunction(L"KeSynchronizeExecution", 0x4390);
  }

  // Hook MSR_LSTAR
  if (KiSystemCall64Ptr == 0) {
    // read msr_lstra values: kiSystemCall64addr
    KiSystemCall64Ptr = UtilReadMsr64(Msr::kIa32Lstar);

    // Something isn't right
    if (KiSystemCall64Ptr == 0) return STATUS_UNSUCCESSFUL;

    HYPERPLATFORM_LOG_DEBUG("Entry Msr_Hook_Dpc_Exec\r\n");

    // Init Msr_Hook
    KeGenericCallDpc(SHpMsrHookCallbackDPC,
                     (PVOID)(ULONG_PTR)SyscallEntryPoint);
  }

  // Enable hook
  if (g_SSDT) status = MsrInitHookType(g_SSDT);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return STATUS_SUCCESS;
}

NTSTATUS MsrInitHookType(
	const PSYSTEM_SERVICE_DESCRIPTOR_TABLE pssdt
) 
{
  if (!NT_SUCCESS(FileMsrHook(pssdt))) {
    HYPERPLATFORM_LOG_DEBUG("Entry Msr_Hook_failure\r\n");
  }
  return STATUS_SUCCESS;
}

NTSTATUS AddMsrHook(
	IN ULONG index, 
	IN PVOID hookPtr, 
	IN CHAR argCount
) 
{
  NTSTATUS status = STATUS_SUCCESS;
  if (index > MAX_SYSCALL_INDEX || hookPtr == NULL)
    return STATUS_INVALID_PARAMETER;
  KIRQL irql = KeGetCurrentIrql();
  if (irql < DISPATCH_LEVEL) irql = KeRaiseIrqlToDpcLevel();
  InterlockedExchange64((PLONG64)&HookTable[index],
                        (LONG64)hookPtr);           // 构造的hook表
  InterlockedExchange8(&ArgTble[index], argCount);  // 参数表
  InterlockedExchange8(&HookEnabled[index], TRUE);  // 是否开始hook

  if (KeGetCurrentIrql() > irql) KeLowerIrql(irql);

  return status;
}


//=======================================================
// Ept Ssdt Hook
//=======================================================
VOID SHpSsdtHookCallbackDPC(
	PRKDPC Dpc, 
	PVOID Context, 
	PVOID SystemArgument1,           
	PVOID SystemArgument2
)
{
  UNREFERENCED_PARAMETER(Dpc);

  UtilVmCall(HypercallNumber::kEpthook, nullptr);

  KeSignalCallDpcSynchronize(SystemArgument2);
  KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS EptSshookEntry(
	void* context
)
{
  // Get a base address of ntoskrnl
  auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);
  if (!nt_base) {
    return STATUS_UNSUCCESSFUL;
  }



  KeGenericCallDpc(SHpSsdtHookCallbackDPC, nullptr);
  return 0;
}