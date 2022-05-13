#include "KernelMemory.h"
#include "ntapi.h"
KernelMemoryOperation::KernelMemoryOperation() {
	this->DeviceHandle = CreateFileW(DEVICE_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (this->DeviceHandle == INVALID_HANDLE_VALUE) {
		this->error = GetLastError();
		printf("Error in KernelMemoryOperation:%d\n", this->error);
		return;
	}

}

DWORD KernelMemoryOperation::Test() {
	pNtDeviceIoControlFile NtDeviceIoControlFile = (pNtDeviceIoControlFile)GetNativeProc("NtDeviceIoControlFile");
	IO_STATUS_BLOCK iosb;
	struct {
		PVOID address;
		SIZE_T size;
		PVOID outData;
		PSIZE_T outSize;
	} input;
	input.address = (PVOID)0xffffffffffffffff;
	input.size = 1234;
	struct {
		PVOID address;
		SIZE_T size;
		PVOID outData;
		PSIZE_T outSize;
	} output;
	printf("%p\n", &input);
	NTSTATUS status = NtDeviceIoControlFile(
		this->DeviceHandle,
		NULL,
		NULL,
		NULL,
		&iosb,
		IOCTL_GTCTL_METHOD_READ_MEMORY,
		&input,
		sizeof(input),
		NULL,
		0
	);
	printf("%p\n", status);
	return 0;
}

DWORD KernelMemoryOperation::GetBytes(
	PVOID address,
	SIZE_T size,
	PBYTE output
) {
	MPEBytes target = MPEBytes::INT64ToBytes((ULONG64)address);
	MPEBytes readSize = MPEBytes::INT16ToBytes(size);
	target.AddBytes(readSize);
	
	DWORD returnSize = 0;
	BOOL IsOk = DeviceIoControl(
		this->DeviceHandle,
		IOCTL_GTCTL_METHOD_READ_MEMORY,
		target.ToBytes(),
		target.size,
		output,
		65535,
		&returnSize,
		NULL
	);
	if (IsOk == FALSE) {
		this->error = GetLastError();
		printf("Error:%d\n", this->error);
		return 0;
	}
	for (int i = 0; i < size; i++) {
		printf("%.2x ", output[i]);
	}
	return returnSize;
}

DWORD KernelMemoryOperation::GetINT16(
	PVOID address,
	PINT16 output
) {
	BYTE tmp[2] = { 0 };
	this->GetBytes(address, sizeof(INT16), tmp);
	*output = MPEBytes::BytesToINT16(tmp);
	return *output;
}

DWORD KernelMemoryOperation::GetINT32(
	PVOID address,
	PINT32 output
) {
	BYTE tmp[4] = { 0 };
	this->GetBytes(address, sizeof(INT16), tmp);
	*output = MPEBytes::BytesToINT32(tmp);
	return *output;
}

DWORD KernelMemoryOperation::GetINT64(
	PVOID address,
	PINT64 output
) {
	BYTE tmp[4] = { 0 };
	this->GetBytes(address, sizeof(INT16), tmp);
	*output = MPEBytes::BytesToINT32(tmp);
	return *output;
}

KernelMemoryOperation::~KernelMemoryOperation() {
	CloseHandle(this->DeviceHandle);

}