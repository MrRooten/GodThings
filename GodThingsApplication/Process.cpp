#include "Process.h"
#include "utils.h"
#include <stdlib.h>
#include <set>
#include "ntapi.h"
#include "sddl.h"
#include "NtSystemInfo.h"
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  int ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);


typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);


_SecurityState::_SecurityState() {
	this->groups = (PTOKEN_GROUPS)malloc(sizeof(TOKEN_GROUPS));
	this->groupsWithPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)malloc(sizeof(TOKEN_GROUPS_AND_PRIVILEGES));
	this->integrity = (PTOKEN_MANDATORY_LABEL)malloc(sizeof(TOKEN_MANDATORY_LABEL));
	this->privileges = (PTOKEN_PRIVILEGES)malloc(sizeof(PTOKEN_PRIVILEGES));
}

_SecurityState::~_SecurityState() {
	free(this->groups);
	free(this->groupsWithPrivileges);
	free(this->integrity);
	free(this->privileges);
}
std::vector<std::wstring> _SecurityState::GetSIDsString() {
	std::vector<std::wstring> res;
	for (int i = 0; i < this->groups->GroupCount; i++) {
		LPWSTR buffer = NULL;
		if (!ConvertSidToStringSidW(this->groups->Groups[i].Sid, &buffer)) {
			continue;
		}
		if (buffer == NULL) {
			continue;
		}

		res.push_back(buffer);
		LocalFree(buffer);
	}
	return res;
}


std::vector<std::wstring> _SecurityState::GetPrivilegesAsString() {
	std::vector<std::wstring> res;
	for (int i = 0; i < this->privileges->PrivilegeCount; i++) {
		WCHAR privilegeName[100] = { 0 };
		DWORD size = 100;
		if (!LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, privilegeName, &size)) {
			continue;
		}
		res.push_back(privilegeName);
	}
	return res;
}

std::wstring _SecurityState::GetIntegrityAsString() {
	LPWSTR buffer = NULL;
	if (!ConvertSidToStringSidW(this->integrity->Label.Sid, &buffer)) {
		return L"";
	}
	if (buffer == NULL) {
		return L"";
	}

	std::wstring res = buffer;
	LocalFree(buffer);
	return res;
}
void Process::InitProcessStaticState() {
	this->SetProcessSecurityState();
	this->SetProcessUserName();
	this->SetProcessImageState();
}

Process::Process(PSYSTEM_PROCESS_INFORMATION pInfo, ProcessManager* procMgr) {
	this->processId = (PID)pInfo->UniqueProcessId;
	this->processName = pInfo->ImageName.Buffer;
	this->processesManager = procMgr;
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (this->hProcess == NULL) {
		this->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (this->hProcess == NULL) {
			this->hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
		}
		else {
			this->processRights = PROCESS_QUERY_INFORMATION;
		}
	}
	else {
		this->processRights = PROCESS_ALL_ACCESS;
	}


	if (this->hProcess == NULL) {
		//fails to get process handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcess:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return;
	}

	if (!OpenProcessToken(this->hProcess, TOKEN_QUERY, &this->processToken)) {
		//fails to get process token handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcessToken:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
	}
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;
}

Process::Process(PID processId, ProcessManager* processesManager) {
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (this->hProcess == NULL) {
		this->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (this->hProcess == NULL) {
			this->hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
		}
		else {
			this->processRights = PROCESS_QUERY_INFORMATION;
		}
	}
	else {
		this->processRights = PROCESS_ALL_ACCESS;
	}


	if (this->hProcess == NULL) {
		//fails to get process handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcess:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return;
	}

	if (!OpenProcessToken(this->hProcess, TOKEN_QUERY, &this->processToken)) {
		//fails to get process token handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcessToken:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
	}

	this->processId = processId;
	this->processesManager = processesManager;
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;

}

Process::Process(PID processId) {
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (this->hProcess == NULL) {
		this->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (this->hProcess == NULL) {
			this->hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
		}
		else {
			this->processRights = PROCESS_QUERY_INFORMATION;
		}
	}
	else {
		this->processRights = PROCESS_ALL_ACCESS;
	}


	if (this->hProcess == NULL) {
		//fails to get process handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcess:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return;
	}

	if (!OpenProcessToken(this->hProcess, TOKEN_QUERY, &this->processToken)) {
		//fails to get process token handle
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error occurs in OpenProcessToken:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
	}

	this->processId = processId;
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;
}

Process::~Process() {
	CloseHandle(this->hProcess);

	if (memoryState != nullptr)
		delete this->memoryState;

	if (ioState != nullptr)
		delete this->ioState;

	if (cpuState != nullptr)
		delete this->cpuState;

	if (securityState != nullptr)
		delete this->securityState;

	if (imageState != nullptr)
		delete this->imageState;

	if (handleState != nullptr) {
		if (handleState->handles != nullptr)
			free(handleState->handles);
		
		delete handleState;
	}
		

	if (latestCpuState != nullptr)
		delete latestCpuState;

	
}


DWORD Process::KillProcess() {
	if (!TerminateProcess(this->hProcess, 0)) {
		return GetLastError();
	}
	return 0;
}

DWORD Process::UpdateInfo() {
	this->SetProcessMemoryState();
	this->SetProcessCPUState();
	return 0;
}

BOOL Process::SetThreads() {
	this->threads = this->processesManager->GetThreadsByPID(this->processId);
	return TRUE;
}

LSA_HANDLE GetPolicyHandle() {
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	TCHAR* SystemName = NULL;
	USHORT SystemNameLength;
	LSA_UNICODE_STRING lusSystemName;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	ntsResult = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES, &lsahPolicyHandle);

	if (ntsResult != CMC_STATUS_SUCCESS) {
		_tprintf(_T("OpenPolicy returned %lu"), LsaNtStatusToWinError(ntsResult));
		return NULL;
	}

	return lsahPolicyHandle;
}

DWORD Process::SuspendProcess() {
	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandleW(L"ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(this->hProcess);
	return 0;
}

DWORD Process::ResumeProcess() {
	NtSuspendProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
		GetModuleHandleW(L"ntdll"), "NtResumeProcess");
	pfnNtResumeProcess(this->hProcess);
	return 0;
}
DWORD Process::SetProcessUserName() {
	SetLastError(ERROR_SUCCESS);
	DWORD res = 0;
	LSA_HANDLE policyHandle;
	if (hProcess == NULL) {
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error in Setting Process user name when using Handle:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
	}
	HANDLE processToken;
	DWORD status;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &processToken)) {
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Can not Call OpenProcessToken:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return GetLastError();
	}
	
	TOKEN_USER tokenUser;
	PTOKEN_USER pTokenUser;
	DWORD dwSize;
	GetTokenInformation(processToken, TokenUser, &tokenUser, 0, &dwSize);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR,dwSize);
		GetTokenInformation(processToken, TokenUser, pTokenUser, dwSize, &dwSize);
	}
	else {
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error Happen in GetTokenInformation:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return GetLastError();
	}
	
	policyHandle = GetPolicyHandle();
	if (policyHandle == NULL) {
		//FAILS TO GET POLICY HANDLE
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error Happen in GetPolicyHandle:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return GetLastError();
	}

	if (processToken == NULL) {
		return NULL;
	}
	
	PSID sids[1];
	sids[0] = pTokenUser->User.Sid;
	PLSA_TRANSLATED_NAME names = NULL;
	PLSA_REFERENCED_DOMAIN_LIST referencedNames = NULL;
	LPTSTR Name;
	PWSTR userName = NULL;
	
	if (LsaLookupSids(policyHandle, 1, &pTokenUser->User.Sid, &referencedNames, &names) >= 0) {
		if (names[0].Use != SidTypeInvalid && names[0].Use != SidTypeUnknown) {
			if (userName == NULL) {
				userName = names[0].Name.Buffer;
				this->userName = userName;
			}
		}
	}
	else {
		res = NULL;
	}
	
	if (pTokenUser != NULL) {
		GlobalFree(pTokenUser);
	}

	if (names) {
		LsaFreeMemory(names);
	}

	if (referencedNames) {
		LsaFreeMemory(referencedNames);
	}
	
	return 0;
}

DWORD Process::SetProcessSecurityState() {
	SetLastError(ERROR_SUCCESS);
	if (this->securityState == nullptr) {
		//if fail to create security State
	}
	DWORD dwTokenGroup = 0;
	DWORD status = ERROR_SUCCESS;
	if (this->processToken == NULL) {
		return 0;
	}
	if (!GetTokenInformation(processToken, TokenGroups, securityState->groups, sizeof(TOKEN_GROUPS), &dwTokenGroup)) {
		status = GetLastError();
	}

	if (status == ERROR_INSUFFICIENT_BUFFER) {
		this->securityState->groups = (PTOKEN_GROUPS)realloc(securityState->groups, dwTokenGroup);
		if (this->securityState->groups == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not alloc TOKEN_GROUPS:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(),GetLastErrorAsString());
			return GetLastError();
		}
		
		if (!GetTokenInformation(processToken, TokenGroups, securityState->groups, dwTokenGroup, &dwTokenGroup)) {
			status = GetLastError();
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Something occurs in GetTokenInformation for TOKEN_GROUPS:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, status,GetLastErrorAsString());
		}
	}
	DWORD dwTokenSessionId = 0;
	if (!GetTokenInformation(processToken, TokenSessionId, &this->securityState->Session, sizeof(DWORD), &dwTokenSessionId)) {
		status = GetLastError();
	}

	DWORD dwImpersonationLevel;
	if (!GetTokenInformation(processToken, TokenImpersonationLevel, &this->securityState->impersonationLevel,
		sizeof(SECURITY_IMPERSONATION_LEVEL), &dwImpersonationLevel)) {

	}

	DWORD dwTokenGroupsAndPrivileges = 0;
	if (!GetTokenInformation(processToken, TokenGroupsAndPrivileges, securityState->groupsWithPrivileges, 0, &dwTokenGroupsAndPrivileges)) {
		status = GetLastError();
	}

	if (status == ERROR_INSUFFICIENT_BUFFER) {
		this->securityState->groupsWithPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)
			realloc(securityState->groupsWithPrivileges, dwTokenGroupsAndPrivileges);
		if (this->securityState->groupsWithPrivileges == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not alloc TOKEN_GROUPS_AND_PRIVILEGES:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenGroupsAndPrivileges, securityState->groupsWithPrivileges, dwTokenGroupsAndPrivileges, &dwTokenGroupsAndPrivileges)) {
			status = GetLastError();
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Something occurs in GetTokenInformation for TokenGroupsAndPrivileges:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, status, GetLastErrorAsString());
		}
	}

	DWORD dwPrivileges = 0;
	if (!GetTokenInformation(processToken, TokenPrivileges, securityState->privileges, 0, &dwPrivileges)) {
		status = GetLastError();
	}

	if (status == ERROR_INSUFFICIENT_BUFFER) {
		this->securityState->privileges = (PTOKEN_PRIVILEGES)
			realloc(securityState->privileges, dwPrivileges);
		if (this->securityState->privileges == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not alloc TOKEN_PRIVILEGES:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenPrivileges, securityState->privileges, dwPrivileges, &dwPrivileges)) {
			status = GetLastError();
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Something occurs in GetTokenInformation for TokenPrivileges:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, status, GetLastErrorAsString());
		}
	}

	DWORD dwTokenMandatoryLabel = 0;
	if (!GetTokenInformation(processToken, TokenIntegrityLevel, securityState->integrity, 0, &dwTokenMandatoryLabel)) {
		status = GetLastError();
	}

	if (status == ERROR_INSUFFICIENT_BUFFER) {
		this->securityState->integrity = (PTOKEN_MANDATORY_LABEL)
			realloc(securityState->integrity, dwTokenMandatoryLabel);
		if (this->securityState->integrity == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not alloc TOKEN_MANDATORY_LABEL:%d,%s", GetLastError(), GetLastErrorAsString());
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenIntegrityLevel, securityState->integrity, dwTokenMandatoryLabel, &dwTokenMandatoryLabel)) {
			status = GetLastError();
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Something occurs in GetTokenInformation for TokenIntegrityLevel:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, status, GetLastErrorAsString());
		}
	}
	return 0;
}

void Process::ChangeProcessPriority(Priority priority) {
	if (!SetPriorityClass(this->hProcess, priority)) {

	}
}

Priority Process::GetPriority() {
	return GetPriorityClass(this->hProcess);
}

Affinity Process::GetAffinity() {
	DWORD_PTR affinity;
	DWORD_PTR systemAffinity;
	if (!GetProcessAffinityMask(this->hProcess, &affinity, &systemAffinity)) {

	}

	return affinity;
}

void Process::SetAffinity(Affinity affinity) {
	//if (!SetProcessAffinityMask(this->thisProcess, (DWORD)&this->affinity)) {
		//when can't set process affinity mask
	//}
}


DWORD Process::SetProcessCPUState() {
	DWORD res = 0;
	if (this->hProcess == NULL) {
		return 0;
	}
	if (this->latestCpuState == NULL) {
		//error when alloc CPUState struct
	}

	if (cpuState != NULL && latestCpuState != NULL)
		*cpuState = *latestCpuState;

	if (!GetProcessTimes(this->hProcess, &latestCpuState->createTime, &latestCpuState->exitTime, &latestCpuState->kernelTime, &latestCpuState->userTime)) {
		//error when get Processes times
		res = GetLastError();
		return res;
	}

	PROCESS_PRIORITY_CLASS priority;
	DWORD size;
	pNtQueryInformationProcess NtQueryInfomationProcess;
	NtQueryInfomationProcess = (pNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	if (NtQueryInfomationProcess == NULL) {
		return GetLastError();
	}
	NTSTATUS status = NtQueryInfomationProcess(
		this->hProcess,
		ProcessPriorityClass,
		&priority,
		sizeof(PROCESS_PRIORITY_CLASS),
		&size
	);
	if (status != 0) {
		return NtStatusHandler(status);
	}
	this->latestCpuState->priority = priority.PriorityClass;
	return res;
}

DWORD Process::SetProcessHandleState() {
	NTSTATUS status;
	ULONG returnLength = 0;
	ULONG attempts = 0;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->processId);
	if (hProcess == NULL) {
		return GetLastError();
	}
	if (this->handleState->handles == NULL) {
		this->handleState->_bufferSize = 0x8000;
		this->handleState->handles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)malloc(this->handleState->_bufferSize);
	}
	pNtQueryInformationProcess NtQueryInfomationProcess;
	NtQueryInfomationProcess = (pNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	status = NtQueryInfomationProcess(
		hProcess,
		ProcessHandleInformation,
		this->handleState->handles,
		this->handleState->_bufferSize,
		&returnLength
	);

	while (status == STATUS_INFO_LENGTH_MISMATCH && attempts < 8)
	{
		free(this->handleState->handles);
		this->handleState->_bufferSize = returnLength;
		this->handleState->handles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)malloc(this->handleState->_bufferSize);

		status = NtQueryInfomationProcess(
			hProcess,
			ProcessHandleInformation,
			this->handleState->handles,
			this->handleState->_bufferSize,
			&returnLength
		);

		attempts++;
	}

	if (NT_SUCCESS(status))
	{
		// NOTE: This is needed to workaround minimal processes on Windows 10
		// returning STATUS_SUCCESS with invalid handle data. (dmex)
		// NOTE: 21H1 and above no longer set NumberOfHandles to zero before returning
		// STATUS_SUCCESS so we first zero the entire buffer using PhAllocateZero. (dmex)
		if (this->handleState->handles->NumberOfHandles == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			free(this->handleState->handles);
			this->handleState->handles = NULL;
		}
		
	}
	else
	{
		free(this->handleState->handles);
		
		this->handleState = NULL;
	}
	CloseHandle(hProcess);
	return NtStatusHandler(status);
}

DWORD Process::SetProcessImageState() {
	DWORD res = 0;
	WCHAR path[2048];
	if (this->imageState == NULL) {
		//error when alloc ImageState struct
		SetLastError(6);
		return GetLastError();
	}


	//Get cmdline of process
	PUNICODE_STRING123 cmdline = (PUNICODE_STRING123)LocalAlloc(GPTR, 1000);
	DWORD size = 0;
	pfnNtQueryInformationProcess NtQueryInformation = (pfnNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	do {
		if (NtQueryInformation != NULL) {
			NTSTATUS status = NtQueryInformation(hProcess, ProcessCommandLineInformation, cmdline, 1000, &size);
			if (NtStatusHandler(status) == ERROR_INSUFFICIENT_BUFFER) {
				cmdline = (PUNICODE_STRING123)LocalReAlloc(cmdline, size, GPTR | GMEM_MOVEABLE);
				NTSTATUS status = NtQueryInformation(hProcess, ProcessCommandLineInformation, cmdline, 1000, &size);
			}
			else if (NtStatusHandler(status) == ERROR_SUCCESS) {
				if (cmdline->Buffer == NULL) {
					break;
				}
				imageState->cmdline = cmdline->Buffer;
				break;
			}
			else {
				break;
			}
			
		}
	} while (0);
	//Get path
	
	if (!GetProcessImageFileNameW(hProcess, path, 2048)) {
		res = GetLastError();
	}
	else {
		imageState->imageFileName = path;
	}
	ZeroMemory(path, sizeof(path));
	size = sizeof(path);
	if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
		res = GetLastError();
	}
	else {
		imageState->filePath = path;
	}
	LocalFree(cmdline);
	return res;

}

DWORD Process::SetProcessMemoryState() {
	ZeroMemory(&this->pMemoryCounters, sizeof(this->pMemoryCounters));
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	if (NtQueryInformationProcess != NULL) {
		DWORD size = 0;
		VM_COUNTERS_EX2 counters2 = { 0 };
		NTSTATUS status = NtQueryInformationProcess(this->hProcess, ProcessVmCounters, &counters2, sizeof(VM_COUNTERS_EX2), &size);
		if (status != 0) {
			return NtStatusHandler(status);
		}
		memcpy_s(this->memoryState, sizeof(MemoryState), &counters2, sizeof(VM_COUNTERS_EX2));
		this->memoryState->PeakPagefileUsage = counters2.CountersEx.PeakPagefileUsage;
		this->memoryState->VirtualSize = counters2.CountersEx.VirtualSize;
		this->memoryState->PageFaultCount = counters2.CountersEx.PageFaultCount;
		this->memoryState->PeakWorkingSetSize = counters2.CountersEx.PeakWorkingSetSize;
		this->memoryState->QuotaPeakPagedPoolUsage = counters2.CountersEx.QuotaPeakPagedPoolUsage;
		this->memoryState->QuotaPagedPoolUsage = counters2.CountersEx.QuotaPagedPoolUsage;
		this->memoryState->QuotaPeakNonPagedPoolUsage = counters2.CountersEx.QuotaPeakNonPagedPoolUsage;
		this->memoryState->QuotaNonPagedPoolUsage = counters2.CountersEx.QuotaNonPagedPoolUsage;
		this->memoryState->PagefileUsage = counters2.CountersEx.PagefileUsage;
		this->memoryState->PeakPagefileUsage = counters2.CountersEx.PeakPagefileUsage;
		this->memoryState->PrivateUsage = counters2.CountersEx.PrivateUsage;
		this->memoryState->PrivateWorkingSetSize = counters2.PrivateWorkingSetSize;
		this->memoryState->SharedCommitUsage = counters2.SharedCommitUsage;
	}
	else {
		return GetLastError();
	}

	return ERROR_SUCCESS;
}

DWORD Process::SetProcessIOState() {
	ZeroMemory(this->ioState, sizeof(IOState));
	IO_COUNTERS ioCounters;
	if (!GetProcessIoCounters(this->hProcess, &ioCounters)) {
		return GetLastError();
	}

	ioState->ReadTransferCount = ioCounters.ReadTransferCount;
	ioState->WriteTransferCount = ioCounters.WriteTransferCount;
	ioState->OtherTransferCount = ioCounters.OtherTransferCount;
	ioState->ReadOperationCount = ioCounters.ReadOperationCount;
	ioState->WriteOperationCount = ioCounters.WriteOperationCount;
	ioState->OtherOperationCount = ioCounters.OtherOperationCount;
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return GetLastError();
	}
	IO_PRIORITY_HINT ioPriority;
	DWORD size;
	NTSTATUS status = NtQueryInformationProcess(this->hProcess, ProcessIoPriority, &ioPriority, sizeof(IO_PRIORITY_HINT), &size);
	if (status != 0) {
		return NtStatusHandler(status);
	}
	this->ioState->priority = ioPriority;
	return NtStatusHandler(status);
}




//DWORD Process::SetProcessHandlesState() {
//	PPROCESS_HANDLE_SNAPSHOT_INFORMATION handles;
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processId);
//	NTSTATUS status = EnumProcessHandles(
//		hProcess,
//		&handles
//	);
//	if (hProcess != NULL) {
//		CloseHandle(hProcess);
//	}
//	PSYSTEM_HANDLE_INFORMATION_EX convertedHandles = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(sizeof(SYSTEM_HANDLE_INFORMATION_EX) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (handles->NumberOfHandles));
//	if (convertedHandles == NULL) {
//		Logln(DEBUG_LEVEL, 
//			L"Can not alloc space for SYSTEM_HANDLE_INFORMATION_EX:%d,%s", 
//			GetLastError(), 
//			GetLastErrorAsString());
//		return GetLastError();
//	}
//	convertedHandles->NumberOfHandles = handles->NumberOfHandles;
//
//
//	for (int i = 0; i < handles->NumberOfHandles; i++) {
//		convertedHandles->Handles[i].Object = 0;
//		convertedHandles->Handles[i].UniqueProcessId = (ULONG_PTR)this->processId;
//		convertedHandles->Handles[i].HandleValue = (ULONG_PTR)handles->Handles[i].HandleValue;
//		convertedHandles->Handles[i].GrantedAccess = handles->Handles[i].GrantedAccess;
//		convertedHandles->Handles[i].CreatorBackTraceIndex = 0;
//		convertedHandles->Handles[i].ObjectTypeIndex = (USHORT)handles->Handles[i].ObjectTypeIndex;
//		convertedHandles->Handles[i].HandleAttributes = handles->Handles[i].HandleAttributes;
//	}
//	this->handleState->handles = convertedHandles;
//	return 0;
//}

BOOL Process::CreateDump(LPTSTR filename, MINIDUMP_TYPE dumpType) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, this->processId);
	if (hProcess = NULL) {
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Can open process in CreateDump:%d,%s,%d", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString(), __LINE__);
		return 0;
	}
	HANDLE dumpFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dumpFile == INVALID_HANDLE_VALUE) {
		//fails to create a file handle
		return FALSE;
	}

	if (!MiniDumpWriteDump(hProcess, this->processId, dumpFile, dumpType, NULL, NULL, NULL)) {
		//fails to dump
		return FALSE;
	}

	CloseHandle(dumpFile);
	return TRUE;
}

PID Process::GetPID() {
	return processId;
}

std::wstring Process::GetUser() {
	if (this->userName.size() != 0) {
		return this->userName;
	}
	this->SetProcessUserName();
	return this->userName;
}
SecurityState* Process::GetSecurityState() {
	if (this->securityState != NULL) {
		return this->securityState;
	}
	this->SetProcessSecurityState();
	return this->securityState;
}
ImageState* Process::GetImageState() {
	if (this->imageState != NULL) {
		return this->imageState;
	}
	this->SetProcessImageState();
	return this->imageState;
}
HandleState* Process::GetHandlesState() {
	this->SetProcessHandleState();
	return this->handleState;
}
IOState* Process::GetIOState() {
	this->SetProcessIOState();
	return this->ioState;
}
MemoryState* Process::GetMemoryState() {
	this->SetProcessMemoryState();
	return this->memoryState;
}

CPUState* Process::GetCPUState() {
	this->SetProcessCPUState();
	return this->cpuState;
}

DWORD Process::ReadMemoryFromAddress(PVOID address, PBYTE data,size_t size) {
	DWORD status = 0;
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, this->processId);
	if (hProcess == NULL) {
		Logln(INFO_LEVEL, L"[%s:%s:%d]:Access denied to process memory",__FILEW__, __FUNCTIONW__, __LINE__ );
		return GetLastError();
	}
	if (!ReadProcessMemory(hProcess, address, data, size, NULL)) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			Logln(INFO_LEVEL, L"[%s:%s:%d]:Access denied to process memory");
		}
		else {
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Error ReadProcessMemory:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		}
	}
	status = GetLastError();
	return status;
}

Thread::Thread(TID tid) {
	this->threadId = tid;
}

Thread::Thread(PSYSTEM_THREAD_INFORMATION pInfo) {
	this->threadId = (TID)pInfo->ClientId.UniqueThread;
	this->processId = (PID)pInfo->ClientId.UniqueProcess;
}
Thread::~Thread() {

}

void Thread::Suspend() {
	if (SuspendThread(this->hThread) == -1) {
		//error when can't suspend thread 
		return;
	}
}

void Thread::Resume() {
	if (ResumeThread(this->hThread) == -1) {
		//error when can't resume thread
		return;
	}
}

void Thread::Terminate() {
	HANDLE hTread = OpenThread(THREAD_TERMINATE, FALSE, this->threadId);
	if (hTread == NULL) {
		Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Can not open thread in Thread::Terminate:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return;
	}
	if (!TerminateThread(hThread, 0)) {
		//error when terminate thread
		Logln(INFO_LEVEL, L"[%s:%s:%d]:Can not terminate the thread:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		return;
	}
}


BOOL ProcessManager::SetAllThreads() {
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	do {
		PID pid = te32.th32OwnerProcessID;
		if (this->threadsMap.count(pid)) {
			threadsMap[pid].push_back(new Thread(te32.th32ThreadID));
		}
		else {
			std::vector<Thread*> _threads;
			threadsMap[pid] = _threads;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	return TRUE;
}

ProcessManager* ProcessManager::_mgr = NULL;
ProcessManager* ProcessManager::GetMgr() {
	if (ProcessManager::_mgr != NULL) {
		return ProcessManager::_mgr;
	}
	ProcessManager::_mgr = new ProcessManager();
}

ProcessManager::ProcessManager() {

}

ProcessManager::~ProcessManager() {
	for (auto i : processesMap) {
		delete i.second;
	}

	for (auto i : threadsMap) {
		for (auto p : i.second) {
			delete p;
		}
	}
}

BOOL ProcessManager::SetAllProcesses() {
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	//For keep the orignal Process object that existed before this function is called so delete the processes
	//that not exist anymore,new the processes that not exist before this function is called.
	std::set<PID> newUpdatePids;
	do {
		PID pid = pe32.th32ProcessID;
		newUpdatePids.insert(pid);
		PID parentPid = pe32.th32ParentProcessID;
		if (processesMap.count(pid) == 0) {
			processesMap[pid] = new Process(pid, this);
			processesMap[pid]->processId = pid;
			processesMap[pid]->parentPID = parentPid;
#ifndef UNICODE
			processesMap[pid]->processName = s2ws(pe32.szExeFile);
#else
			processesMap[pid]->processName = pe32.szExeFile;
#endif // UNICODE
			processesMap[pid]->InitProcessStaticState();
			processesMap[pid]->SetProcessCPUState();
		}
	} while (Process32Next(hProcessSnap, &pe32));

	for (auto oldPid : this->lastUpdatePids) {
		if (newUpdatePids.count(oldPid) == 0) {
			delete processesMap[oldPid];
			processesMap.erase(oldPid);
		}
	}

	this->lastUpdatePids = newUpdatePids;
	return TRUE;
}

DWORD ProcessManager::SetAllProcesses2() {
	DWORD dwSize = 0x1000;
	pNtQuerySystemInformation NtQuerySystemInformation;
	NtQuerySystemInformation = (pNtQuerySystemInformation)GetNativeProc("NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return GetLastError();
	}
	PSYSTEM_PROCESS_INFORMATION pProcessesInfo = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc(GPTR,dwSize);
	if (pProcessesInfo == NULL) {
		return GetLastError();
	}
	NTSTATUS status = NtQuerySystemInformation(
		SystemProcessInformation,
		pProcessesInfo,
		dwSize,
		&dwSize
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pProcessesInfo = (PSYSTEM_PROCESS_INFORMATION)LocalReAlloc(pProcessesInfo, dwSize, GPTR | GMEM_MOVEABLE);
		if (pProcessesInfo == NULL) {
			return GetLastError();
		}
		status = NtQuerySystemInformation(
			SystemProcessInformation,
			pProcessesInfo,
			dwSize,
			&dwSize
		);
		if (NtStatusHandler(status) != ERROR_SUCCESS) {
			SetLastError(NtStatusHandler(status));
			return NtStatusHandler(status);
		}
	}
	else if (NtStatusHandler(status) != ERROR_SUCCESS){
		SetLastError(NtStatusHandler(status));
		return NtStatusHandler(status);
	}

	PSYSTEM_PROCESS_INFORMATION pCurProcess = pProcessesInfo;
	while (pCurProcess->NextEntryOffset != 0) {
		GTPrintln(L"%s", pCurProcess->ImageName.Buffer);
		PID pid = (PID)pCurProcess->UniqueProcessId;
		for (int i = 0; i < pCurProcess->NumberOfThreads; i++) {
			threadsMap[pid].push_back(new Thread(&pCurProcess->Threads[i]));
		}
		pCurProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurProcess + pCurProcess->NextEntryOffset);
	}
	LocalFree(pProcessesInfo);
	return 0;
}
std::vector<Thread*>* ProcessManager::GetThreadsByPID(PID pid) {
	return &this->threadsMap[pid];
}

void ProcessManager::UpdateInfo() {
	this->SetAllProcesses();
}
#include "VerifyUtils.h"
bool _ImageState::IsSigned() {
	if (this->filePath.size() == 0) {
		return true;
	}
	if (VerifyEmbeddedSignature(this->filePath.c_str())) {
		return true;
	}
	return false;
}
