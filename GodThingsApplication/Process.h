#pragma once
#ifndef _PROCESS_H
#define _PROCESS_H
#include "public.h"
#include <minidumpapiset.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <WinBase.h>
#include <Psapi.h>

#include <WinUser.h>
#include <winnt.h>
#include <fileapi.h>

#include <tchar.h>
#include <wchar.h>
#include <stdlib.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <iostream>
#include <NTSecAPI.h>
#include "SystemInfo.h"
#include "NtProcessInfo.h"
#include "NtThreadInfo.h"
#include "FileInfo.h"
#include "VerifyUtils.h"
#define MAX_FILE_LENGTH 4096
#define MAX_USERNAME_LENGTH 255
#define MAX_PROCESS_NAME_LENGTH 255
#define MAX_CMDLINE_LENGTH 2048
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#pragma comment(lib,"dbghelp.lib")

typedef void (*processCallback)(PROCESSENTRY32 processEntry);
typedef unsigned int PID;
typedef unsigned int TID;
typedef long long int Affinity;
typedef DWORD Priority;
typedef ULONGLONG MemoryUsage;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  int ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
);
typedef struct _SecurityState {
	PTOKEN_GROUPS groups;
	DWORD Session;

	SECURITY_IMPERSONATION_LEVEL impersonationLevel;
	PTOKEN_GROUPS_AND_PRIVILEGES groupsWithPrivileges;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_MANDATORY_LABEL integrity;
	_SecurityState();
	~_SecurityState();
	std::vector<std::wstring> GetSIDsString();
	std::vector<std::wstring> GetPrivilegesAsString();
	std::wstring GetIntegrityAsString();
}SecurityState;

typedef struct _CPUState {
	FILETIME createTime;
	FILETIME exitTime;
	FILETIME kernelTime;
	FILETIME userTime;

	int priority;
	ULONG64 cycles;
	DWORD recordTime;
}CPUState;

typedef struct _MemoryState {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivateUsage;
	SIZE_T PrivateWorkingSetSize;
	SIZE_T SharedCommitUsage;
}MemoryState;

typedef struct _IOState {
	int priority;
	ULONGLONG ReadOperationCount;
	ULONGLONG WriteOperationCount;
	ULONGLONG OtherOperationCount;
	ULONGLONG ReadTransferCount;
	ULONGLONG WriteTransferCount;
	ULONGLONG OtherTransferCount;
}IOState;

typedef struct _HandleState {
	int numOfHandles;
	int PeakHandles;
	int GDIHandles;
	int USERHandles;
	DWORD _bufferSize;
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION handles;
	
}HandleState;

typedef struct _ImageState {
	std::wstring imageFileName;
	std::wstring filePath;
	std::wstring GetFilePath();
	//TCHAR path[MAX_PATH];
	std::wstring cmdline;
	SignatureInfomation* info = NULL;
	//TCHAR currentDirectory[MAX_PATH];
	bool IsSigned();
	
	std::wstring GetSignInfo();
	~_ImageState();
}ImageState;


class Thread;
class ProcessManager;
class Process {
	std::vector<Thread> _threads;
public:
	std::vector<Thread*>* threads;
	
	PID processId;
	std::wstring processName;
	std::wstring userName;
	Process* parent = nullptr;
	PID parentPID;
	std::vector<Process*>* childProcesses = nullptr;
	MemoryState* memoryState = new MemoryState();
	CPUState* cpuState = new CPUState();
	CPUState* latestCpuState = new CPUState();
	IOState* ioState = new IOState();
	HandleState* handleState = new HandleState();
	ImageState* imageState = new ImageState();
	SecurityState* securityState = new SecurityState();
	Process(PID processId, ProcessManager* processesManager);
	Process(PSYSTEM_PROCESS_INFORMATION pInfo, ProcessManager* procMgr);
	Process(PID processId);
	DWORD UpdateInfo();
	DWORD KillProcess();
	DWORD SuspendProcess();
	DWORD ResumeProcess();
	void ChangeProcessPriority(Priority priority);
	void SetAffinity(Affinity affinity);
	Affinity GetAffinity();
	Priority GetPriority();
	BOOL CreateDump(LPTSTR filename, MINIDUMP_TYPE dumpType);

	PID GetPID();
	std::wstring GetUser();
	SecurityState* GetSecurityState();
	ImageState* GetImageState();
	HandleState* GetHandlesState();
	IOState* GetIOState();
	MemoryState* GetMemoryState();
	CPUState* GetCPUState();
	DWORD ReadMemoryFromAddress(PVOID address,PBYTE outData,size_t size);
	//DWORD WriteMemoryToAddress(PVOID address, PBYTE inData,size_t size);
	~Process();
	HANDLE hProcess;
	HANDLE processToken;
	DWORD processRights;
	//TOKEN_USER* tokenUser;
	PROCESS_MEMORY_COUNTERS_EX pMemoryCounters;
	IO_COUNTERS ioCounters;
	//A Pointer to ProcessesMangager
	ProcessManager* processesManager;
	Affinity affinity;
	void InitProcessStaticState();
	//set Process User Name after setting Process Security State
	DWORD SetProcessUserName();
	//set Security State in Process
	DWORD SetProcessSecurityState();
	//set Image State in Process
	DWORD SetProcessImageState();
	//set Hanldes State in Process
	DWORD SetProcessHandleState();
	//set IO State in Process
	DWORD SetProcessIOState();
	//set Memory State in Process
	DWORD SetProcessMemoryState();
	//set CPU State in Process
	DWORD SetProcessCPUState();
	//set Process Session id
	DWORD SetSessionId();
	
	DWORD SetThreads();

	/*PPROCESS_EXTENDED_BASIC_INFORMATION pExtendedBasicInfo = NULL;
	DWORD SetExtendedBasicInfo();
	BOOL IsProtected();
	BOOL IsWow64();
	BOOL IsProcessDeleting();
	BOOL IsCrossSessionCreate();
	BOOL IsFrozen();
	BOOL IsStronglyNamed();
	BOOL IsSecureProcess();
	BOOL IsSubsystemProcess();*/


};

class Thread {
public:
	Thread(TID tid);
	Thread(PSYSTEM_THREAD_INFORMATION pInfo);
	SecurityState* securityState;
	TID threadId;
	PID processId;
	Priority priority;
	ULONG memoryPriority;
	FILETIME createTime;
	FILETIME exitTime;
	FILETIME kernelTime;
	FILETIME userTime;
	ULONG64 cycleTime;
	LPTSTR description;
	DWORD accessRights;
	void Suspend();
	void Resume();
	void Terminate();
	~Thread();
private:
	HANDLE hThread;
	HANDLE threadToken;
	CONTEXT threadContext;
	THREAD_BASIC_INFORMATION basicInfo;
	DWORD SetBasicInfo();
	KERNEL_USER_TIMES kernelUserTime;
	DWORD SetKernelUserTime();
	LONG basePriority;
	DWORD SetBasePriority();
	KAFFINITY affinity;
	DWORD SetAffinity();
	HANDLE impersionationToken;
	DWORD SetImpersionationToken();
	THREAD_TEB_INFORMATION tebInformation;
	DWORD SetTEBInformation();
	THREAD_PERFORMANCE_DATA performanceData;
	DWORD SetPerformanceData();
	THREAD_NAME_INFORMATION nameInformation;
	DWORD SetNameInformation();
	//void SetMemoryPriority();
	//void SetThreadPriority();
	//void SetDescription();
	//void SetThreadContext();
};

class ProcessManager {
public:
	static ProcessManager* _mgr;
	static ProcessManager* GetMgr();
	ProcessManager();
	~ProcessManager();
	std::vector<Thread*>* GetThreadsByPID(PID pid);
	FILETIME systemTime;
	FILETIME userTime;
	FILETIME idleTime;
	void UpdateInfo();
	std::map<PID, Process*> processesMap;
	std::set<PID> lastUpdatePids;
	std::map<PID, std::vector<Thread*>> threadsMap;
	BOOL SetAllThreads();
	BOOL SetAllProcesses();
	DWORD SetAllProcesses2();
};


#endif