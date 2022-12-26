#include "SystemInfo.h"

SystemInfo::SystemInfo() {
	if (NtQuerySystemInformation == NULL) {
		NtQuerySystemInformation = (pNtQuerySystemInformation)GetNativeProc("NtQuerySystemInformation");
		if (NtQuerySystemInformation == NULL) {
			return;
		}
	}
}

SystemInfo::~SystemInfo() {
	if (this->pBasicInfo != NULL) {
		GlobalFree(this->pBasicInfo);
		this->pBasicInfo = NULL;
	}

	if (this->pProcessorInfo != NULL) {
		GlobalFree(this->pProcessorInfo);
		this->pProcessorInfo = NULL;
	}
}
DWORD SystemInfo::SetBasicInfo() {
	if (this->pBasicInfo == NULL)
		this->pBasicInfo = (PSYSTEM_BASIC_INFORMATION)GlobalAlloc(GPTR,sizeof(SYSTEM_BASIC_INFORMATION));

	if (this->pBasicInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize;
	NTSTATUS status;
	status = NtQuerySystemInformation(SystemBasicInformation, this->pBasicInfo, sizeof(SYSTEM_BASIC_INFORMATION), &dwSize);
	if (status != 0) {
		return -1;
	}
	return 0;
}

INT SystemInfo::GetProcessorNumber() {
	if (this->pBasicInfo != NULL)
		return pBasicInfo->NumberOfProcessors;
	return 0;
}


DWORD SystemInfo::SetProcessorInfo() {
	this->pProcessorInfo = (PSYSTEM_PROCESSOR_INFORMATION)GlobalAlloc(GPTR, sizeof(SYSTEM_PROCESSOR_INFORMATION));
	if (this->pProcessorInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = 0;
	status = NtQuerySystemInformation(SystemProcessorInformation, this->pProcessorInfo, sizeof(SYSTEM_PROCESSOR_INFORMATION), &dwSize);
	return NtStatusHandler(status);
}

std::wstring SystemInfo::GetProcessorArch() {
	if (this->pProcessorInfo == NULL) {
		DWORD status = SetProcessorInfo();
		if (status != ERROR_SUCCESS) {
			return L"";
		}
	}

	switch (this->pProcessorInfo->ProcessorArchitecture) {
	case PROCESSOR_ALPHA_21064: {
		return L"ALPHA_21064";
	}
	case PROCESSOR_AMD_X8664: {
		return L"AMD_X8664";
	}
	case PROCESSOR_ARCHITECTURE_ALPHA: {
		return L"ALPHA";
	}
	case PROCESSOR_ARCHITECTURE_ALPHA64: {
		return L"ALPHA64";
	}
	case PROCESSOR_ARCHITECTURE_AMD64: {
		return L"AMD64";
	}
	case PROCESSOR_ARCHITECTURE_ARM: {
		return L"ARM";
	}
	case PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64: {
		return L"ARM32_ON_WIN64";
	}
	case PROCESSOR_ARCHITECTURE_ARM64: {
		return L"ARM64";
	}
	case PROCESSOR_ARCHITECTURE_IA32_ON_ARM64: {
		return L"IA32_ON_ARM64";
	}
	case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64: {
		return L"IA32_ON_WIN64";
	}
	case PROCESSOR_ARCHITECTURE_IA64: {
		return L"IA64";

	}
	case PROCESSOR_ARCHITECTURE_INTEL: {
		return L"INTEL";
	}
	case PROCESSOR_ARCHITECTURE_MIPS: {
		return L"MIPS";
	}
	case PROCESSOR_ARCHITECTURE_MSIL: {
		return L"MSIL";
	}
	case PROCESSOR_ARCHITECTURE_NEUTRAL: {
		return L"NEUTRAL";
	}
	}
	return L"";
}

DWORD SystemInfo::SetPerformanceInfo() {
	this->pPerformanceInfo = (PSYSTEM_PERFORMANCE_INFORMATION)GlobalAlloc(GPTR, sizeof(SYSTEM_PERFORMANCE_INFORMATION));
	if (this->pPerformanceInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize;
	NTSTATUS status;
	status = NtQuerySystemInformation(SystemPerformanceInformation, this->pPerformanceInfo, sizeof(SYSTEM_PERFORMANCE_INFORMATION), &dwSize);
	return NtStatusHandler(status);
}

DWORD SystemInfo::SetTimeOfDayInfo() {
	if (this->pTimeOfDayInfo == NULL)
		this->pTimeOfDayInfo = (PSYSTEM_TIMEOFDAY_INFORMATION)GlobalAlloc(GPTR, sizeof(SYSTEM_TIMEOFDAY_INFORMATION));

	if (this->pTimeOfDayInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = 0;
	status = NtQuerySystemInformation(SystemTimeOfDayInformation, this->pTimeOfDayInfo, sizeof SYSTEM_TIMEOFDAY_INFORMATION, &dwSize);
	return NtStatusHandler(status);
}

DWORD SystemInfo::SetProcessorPerformanceInfo() {
	if (this->pProcessPerformanceInfo == NULL)
		this->pProcessPerformanceInfo = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)\
			GlobalAlloc(GPTR, sizeof SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
	if (this->pProcessPerformanceInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = 0;
	status = NtQuerySystemInformation(SystemProcessorPerformanceInformation,
		this->pProcessPerformanceInfo,
		sizeof SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION,
		&dwSize);
	return NtStatusHandler(status);
}


DWORD SystemInfo::SetFlagsInfo() {
	if (this->pFlagsInfo == NULL) {
		this->pFlagsInfo = (PSYSTEM_FLAGS_INFORMATION)\
			LocalAlloc(GPTR, sizeof SYSTEM_FLAGS_INFORMATION);
	}

	if (this->pFlagsInfo == NULL) {
		return GetLastError();
	}
	DWORD dwSize = 0;
	NTSTATUS status = 0;
	status = NtQuerySystemInformation(SystemFlagsInformation,
		this->pFlagsInfo,
		sizeof SYSTEM_FLAGS_INFORMATION,
		&dwSize);
	return NtStatusHandler(status);
}

POSVERSIONINFOEXW SystemInfo::GetSystemVersion() {
	POSVERSIONINFOEXW version = nullptr;
	//GetVersionExW((LPOSVERSIONINFOW)&version);
	return version;
}
