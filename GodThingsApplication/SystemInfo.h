#pragma once
#include "NtSystemInfo.h"
#include <string>
#include <map>
#include <vector>
#include <set>
#include "utils.h"
enum FileType {
	SysDirectory=0,
	SysFile=1
};

class SystemInfo {
public:
	SystemInfo();
	~SystemInfo();

	pNtQuerySystemInformation NtQuerySystemInformation;

	PSYSTEM_BASIC_INFORMATION pBasicInfo = NULL;
	DWORD SetBasicInfo();
	INT GetProcessorNumber();

	PSYSTEM_PROCESSOR_INFORMATION pProcessorInfo = NULL;
	DWORD SetProcessorInfo();
	std::wstring GetProcessorArch();


	PSYSTEM_PERFORMANCE_INFORMATION pPerformanceInfo = NULL;
	DWORD SetPerformanceInfo();

	PSYSTEM_TIMEOFDAY_INFORMATION pTimeOfDayInfo = NULL;
	DWORD SetTimeOfDayInfo();

	PSYSTEM_CALL_COUNT_INFORMATION pCallCountInfo = NULL;
	DWORD SetCallCountInfo();

	PSYSTEM_DEVICE_INFORMATION pDeviceInfo = NULL;
	DWORD SetDeviceInfo();

	PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION pProcessPerformanceInfo = NULL;
	DWORD SetProcessorPerformanceInfo();

	PSYSTEM_FLAGS_INFORMATION pFlagsInfo = NULL;
	DWORD SetFlagsInfo();

	PSYSTEM_CALL_TIME_INFORMATION pCallTimeInfo = NULL;
	DWORD SetCallTimeInfo();

	PSYSTEM_VDM_INSTEMUL_INFO pVDMInstemulInfo = NULL;
	DWORD SetVDMInstemulInfo();

	PSYSTEM_FILECACHE_INFORMATION pFileCacheInfo = NULL;
	DWORD SetFileCacheInfo();

	PSYSTEM_BASIC_WORKING_SET_INFORMATION pBasicWorkingSetInfo = NULL;
	DWORD SetBasicWorkingSetInfo();

	PSYSTEM_POOLTAG pPoolTag = NULL;
	DWORD SetPoolTag();

	PSYSTEM_POOLTAG_INFORMATION pPoolTagInfo = NULL;
	DWORD SetPoolTagInfo();

	PSYSTEM_INTERRUPT_INFORMATION pInterruptInfo = NULL;
	DWORD SetInterruptInfo();

	PSYSTEM_DPC_BEHAVIOR_INFORMATION pDPCBehaviorInfo = NULL;
	DWORD SetDPCBehaviorInfo();

	PSYSTEM_HANDLE_INFORMATION pSystemHandleInfoEx = NULL;
	DWORD SetSystemHandles();
	static POSVERSIONINFOEXW GetSystemVersion();
	std::map<DWORD, std::set<std::pair<FileType, GTWString>>> GetSystemLoadedFiles();

};