#include "ThreadInfo.h"

ThreadInfo::ThreadInfo() {
	this->NtQueryInformationThread = (pNtQueryInformationThread)GetNativeProc("NtQueryInformationThread");

	if (this->NtQueryInformationThread == NULL) {
		this->error = GetLastError();
		return ;
	}
}
DWORD ThreadInfo::SetBasicInfo() {
	if (this->pBasicInfo == NULL) {
		this->pBasicInfo = (PTHREAD_BASIC_INFORMATION)GlobalAlloc(GPTR, sizeof THREAD_BASIC_INFORMATION);
		if (this->pBasicInfo == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pBasicInfo, sizeof THREAD_BASIC_INFORMATION);
	}

	if (this->NtQueryInformationThread == NULL) {
		return this->error;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
		FALSE,
		this->tid);
	if (hThread == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, this->pBasicInfo, sizeof(THREAD_BASIC_INFORMATION), &dwSize);
	return NtStatusHandler(status);
}

DWORD ThreadInfo::SetCycleTimeInfo() {
	if (this->pCycleTimeInfo == NULL) {
		this->pCycleTimeInfo = (PTHREAD_CYCLE_TIME_INFORMATION)GlobalAlloc(GPTR, sizeof THREAD_CYCLE_TIME_INFORMATION);
		if (this->pCycleTimeInfo == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pCycleTimeInfo, sizeof THREAD_CYCLE_TIME_INFORMATION);
	}

	if (this->NtQueryInformationThread == NULL) {
		return this->error;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
		FALSE,
		this->tid);
	if (hThread == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = NtQueryInformationThread(hThread, 
		ThreadCycleTime, 
		this->pCycleTimeInfo, 
		sizeof(THREAD_CYCLE_TIME_INFORMATION), 
		&dwSize);
	return NtStatusHandler(status);
}

DWORD ThreadInfo::SetLastSyscallInfo() {
	if (this->pLastSyscallInfo == NULL) {
		this->pLastSyscallInfo = (PTHREAD_LAST_SYSCALL_INFORMATION)GlobalAlloc(GPTR, sizeof THREAD_LAST_SYSCALL_INFORMATION);
		if (this->pLastSyscallInfo == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pLastSyscallInfo, sizeof THREAD_LAST_SYSCALL_INFORMATION);
	}

	if (this->NtQueryInformationThread == NULL) {
		return this->error;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
		FALSE,
		this->tid);
	if (hThread == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = NtQueryInformationThread(hThread, ThreadLastSystemCall, this->pLastSyscallInfo, sizeof(THREAD_LAST_SYSCALL_INFORMATION), &dwSize);
	return NtStatusHandler(status);
}

