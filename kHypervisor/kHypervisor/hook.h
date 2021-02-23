#pragma once
// #include <ntifs.h>
#include <fltKernel.h>

enum HOOK_KIND {

  INST_UNKNOWN = 0,
  INST_MOVE,
  INST_CTLXFER,      // jmp/jcc/call with 32-bit disp
  INST_CTLXFER_REG,  // jmp/call reg or [reg]
  INST_CALL_MEM,     // call [mem]
  INST_JUMP_MEM,     // jmp  [mem]
  INST_SYSCALL,
  INST_RET
};

typedef struct _HOOK_INST {
  ULONG len;
  UCHAR kind;
  UCHAR op1, op2;
  ULONG64 parm;
  LONG* rel32;  // --> 32-bit relocation for control-xfer
  UCHAR* modrm;
  ULONG flags;

} HOOK_INST;

extern "C" {
	NTSTATUS SHInitMsrHook(void* context);
    NTSTATUS EptSshookEntry(void* context);
	NTSTATUS SHDestroyMsrHook();
	NTSTATUS SHRestoreMsrSyscall(IN ULONG index);
    NTSTATUS AddMsrHook(IN ULONG index, IN PVOID hookPtr, IN CHAR argCount);
	PVOID PuGetSSDTEntry(IN ULONG index);
    PVOID UtilKernelBase(OUT PULONG pSize);
    BOOLEAN Hook_Analyze(void* address, BOOLEAN probe_address, BOOLEAN is64,
                            HOOK_INST* inst);

    static BOOLEAN Hook_Tramp_CountBytes(void* SysProc, ULONG* ByteCount,
                                         BOOLEAN is64, BOOLEAN probe);
    }
