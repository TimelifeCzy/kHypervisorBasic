#include "hook.h"
#include "Common.h"
#include "Filehook.h"

// =======================================================================================
typedef NTSTATUS(NTAPI* P_NtClose)(_In_ _Post_ptr_invalid_ HANDLE Handle);
typedef NTSTATUS(NTAPI* P_ZwCreateFile)(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

// =======================================================================================
P_NtClose __sys_NtClose = NULL;
P_ZwCreateFile __sys_NtCreateFile = NULL;

// =======================================================================================
// Hook_Function
// =======================================================================================
NTSTATUS hkNtClose(HANDLE handle);
NTSTATUS NTAPI hkNtCreateFile(_Out_ PHANDLE FileHandle,
                              _In_ ACCESS_MASK DesiredAccess,
                              _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                              _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                              _In_opt_ PLARGE_INTEGER AllocationSize,
                              _In_ ULONG FileAttributes, _In_ ULONG ShareAccess,
                              _In_ ULONG CreateDisposition,
                              _In_ ULONG CreateOptions,
                              _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                              _In_ ULONG EaLength);

// Enable Msr hook
NTSTATUS FileMsrHook(
	const PSYSTEM_SERVICE_DESCRIPTOR_TABLE pssdt
) 
{
  ULONG size = 0;
  PVOID pBase = UtilKernelBase(&size);

  if (pssdt && pBase) {
    const auto ZwCloseindex = SSDTIndex(&ZwClose);
    const auto ZwCreateFileindex = SSDTIndex(&ZwCreateFile);
    if (ZwCloseindex > pssdt->NumberOfServices) return NULL;
    if (ZwCreateFileindex > pssdt->NumberOfServices) return NULL;

    __sys_NtClose =
        (P_NtClose)((PUCHAR)pssdt->ServiceTableBase +
                    (((PLONG)pssdt->ServiceTableBase)[ZwCloseindex] >> 4));
    __sys_NtCreateFile = (P_ZwCreateFile)(
        (PUCHAR)pssdt->ServiceTableBase +
        (((PLONG)pssdt->ServiceTableBase)[ZwCreateFileindex] >> 4));

	AddMsrHook(ZwCloseindex, (PVOID)hkNtClose, 1);
    AddMsrHook(ZwCreateFileindex, (PVOID)hkNtCreateFile, 11);
  }
  return STATUS_SUCCESS;
}

NTSTATUS hkNtCreateFile(_Out_ PHANDLE FileHandle,
                        _In_ ACCESS_MASK DesiredAccess,
                        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                        _In_opt_ PLARGE_INTEGER AllocationSize,
                        _In_ ULONG FileAttributes, _In_ ULONG ShareAccess,
                        _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions,
                        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                        _In_ ULONG EaLength)
{
  DPRINT("[+]hkNtCreateFile - Processid = %d\r\n", PsGetCurrentProcessId());
  return __sys_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                            IoStatusBlock, AllocationSize, FileAttributes,
                            ShareAccess, CreateDisposition, CreateOptions,
                            EaBuffer, EaLength);
}

NTSTATUS hkNtClose(
	HANDLE handle
) 
{
  // DPRINT("[+]NtClose\r\n");
  return __sys_NtClose(handle);
}