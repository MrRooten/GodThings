#pragma once
#include "NtThreadInfo.h"

class ThreadInfo {
public:
	DWORD tid;
	DWORD error = 0;
	pNtQueryInformationThread NtQueryInformationThread;
	
	ThreadInfo();
	PTHREAD_BASIC_INFORMATION pBasicInfo;
	DWORD SetBasicInfo();
	PTHREAD_CYCLE_TIME_INFORMATION pCycleTimeInfo;
	DWORD SetCycleTimeInfo();
	PTHREAD_LAST_SYSCALL_INFORMATION pLastSyscallInfo;
	DWORD SetLastSyscallInfo();
	PTHREAD_NAME_INFORMATION pNameInfo;
	DWORD SetNameInfo();
	PTHREAD_PROFILING_INFORMATION pProfilingInfo;
	DWORD SetProfilingInfo();
};