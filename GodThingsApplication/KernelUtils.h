#pragma once
#ifndef _KERNEL_UTILS_H
#define _KERNEL_UTILS_H


#include "public.h"
#define DEVICE_LINK_NAME L"\\\\.\\Godthings"

static HANDLE hDriverFile = NULL;
DWORD GTDeviceIoControl(
	PVOID InputBuffer,
	SIZE_T InputBufferSize,
	ULONG IoControlCode
);

BOOL HasDriver();

VOID InitKernelUtils();

#endif // !_KERNEL_UTILS_H