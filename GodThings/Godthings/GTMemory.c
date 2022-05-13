#include "GTMemory.h"

NTSTATUS GTReadVirtualMemory(
	_In_ PVOID BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead,
	_In_ KPROCESSOR_MODE AccessMode
) {
	__try {
		ProbeForRead(BaseAddress, BufferSize, sizeof(ULONG));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	memcpy(Buffer, BaseAddress, NumberOfBytesRead);
	return 0;
}
