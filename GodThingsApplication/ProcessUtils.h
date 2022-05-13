#pragma once
#include "public.h"
#include "KernelUtils.h"
#define IOCTL_GTCTL_METHOD_OPEN_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0X804,METHOD_NEITHER,FILE_ANY_ACCESS)
HANDLE GTOpenProcess(DWORD ProcessId, DWORD AccessRight);

