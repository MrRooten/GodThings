#pragma once
#include "utils.h"
#include "KernelUtils.h"


#define IOCTL_GTCTL_METHOD_READ_MEMORY \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCTL_GTCTL_METHOD_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0X801,METHOD_NEITHER,FILE_ANY_ACCESS)
class KernelMemoryOperation {
private:
	HANDLE DeviceHandle;

public:
	KernelMemoryOperation();
	~KernelMemoryOperation();
	DWORD error;
	DWORD GetBytes(
		PVOID address, 
		SIZE_T size, 
		PBYTE output
	);
	DWORD GetINT16(
		PVOID address,
		PINT16 output
	);
	DWORD GetINT32(
		PVOID address,
		PINT32 output
	);
	DWORD GetINT64(
		PVOID address,
		PINT64 output
	);
	DWORD SetBytes(
		PVOID address,
		PBYTE bytes,
		SIZE_T size
	);
	DWORD Test();
};

