#include "KernelUtils.h"
#include "ntapi.h"
#include <stdio.h>
DWORD GTDeviceIoControl(
	PVOID InputBuffer,
	SIZE_T InputBufferSize,
	ULONG IoControlCode
) {
	pNtDeviceIoControlFile NtDeviceIoControlFile = (pNtDeviceIoControlFile)GetNativeProc("NtDeviceIoControlFile");
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtDeviceIoControlFile(
		hDriverFile,
		NULL,
		NULL,
		NULL,
		&iosb,
		IoControlCode,
		InputBuffer,
		InputBufferSize,
		NULL,
		0
	);

	return NtStatusHandler(status);

}

BOOL HasDriver() {

	if (hDriverFile != INVALID_HANDLE_VALUE) {
		return TRUE;
	}
	return FALSE;
}

VOID InitKernelUtils() {
	hDriverFile = CreateFileW(DEVICE_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}