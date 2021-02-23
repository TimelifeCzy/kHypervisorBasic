#pragma once
#include <ntdef.h>
#include "Native.h"

extern "C" {
	// Enable Hook
	NTSTATUS FileMsrHook(const PSYSTEM_SERVICE_DESCRIPTOR_TABLE pssdt);
}