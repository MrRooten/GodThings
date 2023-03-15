#include "Process.h"
#include "Process.h"
#include "Process.h"
#include "utils.h"
#include <stdlib.h>
#include <set>
#include "ntapi.h"
#include "sddl.h"
#include "NtSystemInfo.h"
#include "ProcessUtils.h"
#include "SystemUtils.h"
#include "ObjectInfo.h"
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_UNSUCCESSFUL           ((NTSTATUS)0xC0000001L)
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
std::vector<GTWString> _SecurityState::GetSIDsString() {
	std::vector<GTWString> res;
	for (DWORD i = 0; i < this->groups->GroupCount; i++) {
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


std::vector<GTWString> _SecurityState::GetPrivilegesAsString() {
	std::vector<GTWString> res;
	for (DWORD i = 0; i < this->privileges->PrivilegeCount; i++) {
		WCHAR privilegeName[100] = { 0 };
		DWORD size = 100;
		if (!LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, privilegeName, &size)) {
			continue;
		}
		res.push_back(privilegeName);
	}
	return res;
}

GTWString _SecurityState::GetIntegrityAsString() {
	LPWSTR buffer = NULL;
	if (!ConvertSidToStringSidW(this->integrity->Label.Sid, &buffer)) {
		return L"";
	}
	if (buffer == NULL) {
		return L"";
	}

	GTWString res = buffer;
	LocalFree(buffer);
	return res;
}
void Process::InitProcessStaticState() {
	this->SetProcessSecurityState();
	this->SetProcessUserName();
	this->SetProcessImageState();
}

Process::Process(PSYSTEM_PROCESS_INFORMATION pInfo, ProcessManager* procMgr) {
	this->processId = (PID)reinterpret_cast<size_t>(pInfo->UniqueProcessId);
	this->processName = pInfo->ImageName.Buffer;
	this->processesManager = procMgr;
	this->_cachedHandle = GTOpenProcess(processId, PROCESS_ALL_ACCESS);
	if (this->_cachedHandle != NULL) {
		this->_maxRight = (0x000F0000 | 0x00100000 | 0xFFFF);
	}
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;
}

Process::Process(PID processId, ProcessManager* processesManager) {
	this->_cachedHandle = GTOpenProcess(processId, PROCESS_ALL_ACCESS);
	if (this->_cachedHandle != NULL) {
		this->_maxRight = (0x000F0000 | 0x00100000 | 0xFFFF);
	}

	this->processId = processId;
	this->processesManager = processesManager;
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;

}

Process::Process(PID processId) {
	this->_cachedHandle = GTOpenProcess(processId,  PROCESS_QUERY_LIMITED_INFORMATION);
	if (this->_cachedHandle != NULL) {
		this->_maxRight = PROCESS_QUERY_LIMITED_INFORMATION;
	} 

	this->processId = processId;
	this->affinity = 0;
	this->ioCounters = { 0 };
	this->pMemoryCounters = { 0 };
	this->parentPID = 0;
}

DWORD Process::InjectDll(const LPWSTR filename) {
	HANDLE hProcess = GetCachedHandle(PROCESS_ALL_ACCESS);
	DWORD threadId;
	if (hProcess == NULL) {
		return GetLastError();
	}

	LPVOID loadAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (loadAddr == NULL) {
		CloseHandle(hProcess);
		return GetLastError();
	}
	
	size_t len = (lstrlenW(filename)+1)*(sizeof(wchar_t));
	auto addr = VirtualAllocEx(hProcess, 0, len, MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	DWORD status = this->WriteMemoryToAddress(addr, (PBYTE)filename, len);
	if (status != 0) {
		CloseHandle(hProcess);
		return status;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadAddr, addr, 0, &threadId);
	if (hThread == INVALID_HANDLE_VALUE || hThread == 0) {
		CloseHandle(hProcess);
		return GetLastError();
	}
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}

std::vector<Segment>& Process::GetSegments() {
	this->SetSegments();
	return this->_segments;
}

Process::~Process() {
	DWORD out;
	if (GetHandleInformation(this->_cachedHandle, &out)) {
		CloseHandle(this->_cachedHandle);
	}

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

BOOL Process::Is32Bit() {
	if (this->_is32 != -2) {
		return this->_is32;
	}
	HANDLE hProcess = this->GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	BOOL ret = FALSE;
	if (IsWow64Process(hProcess, &ret)) {
		if (ret == TRUE) {
			this->_is32 = 1;
			return ret;
		}

		auto arch = SystemUtils::GetSystemArchitecture();
		if (arch == PROCESSOR_ARCHITECTURE_AMD64) {
			this->_is32 = false;
		}

		if (arch == PROCESSOR_ARCHITECTURE_INTEL) {
			this->_is32 = true;
		}

		if (arch == PROCESSOR_ARCHITECTURE_IA64) {
			this->_is32 = false;
		}

		return this->_is32;
	}


	return TRUE;
}


DWORD Process::KillProcess() {
	if (!TerminateProcess(this->GetCachedHandle(PROCESS_TERMINATE), 0)) {
		return GetLastError();
	}
	return 0;
}

DWORD Process::UpdateInfo() {
	this->SetProcessMemoryState();
	this->SetProcessCPUState();
	return 0;
}

DWORD Process::SetThreads() {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {
					if (te.th32OwnerProcessID == this->processId) {
						this->_threads.push_back(Thread(te.th32OwnerProcessID,te.th32ThreadID));
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	return 0;
}

DWORD Process::SetSegments() {
	SetLastError(0);
	HANDLE h = GetCachedHandle(PROCESS_QUERY_INFORMATION);
	MEMORY_BASIC_INFORMATION _tmp_info = { 0 };
	SIZE_T len = 0;
	PVOID base = NULL;
	MEMORY_BASIC_INFORMATION _last = { 0 };
	for (int i = 0; i < 10000; i++) {
		VirtualQueryEx(h, base, &_tmp_info, sizeof(MEMORY_BASIC_INFORMATION) * 10);
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			break;
		}
		this->_segments.push_back(Segment(&_tmp_info));
		base = (PVOID)((UINT64)_tmp_info.RegionSize + (UINT64)_tmp_info.BaseAddress);
		_last = _tmp_info;
	}
	
	return GetLastError();
}

HANDLE Process::GetCachedHandle(DWORD accessRight) {
	if ((accessRight | _maxRight) == _maxRight) {
		return this->_cachedHandle;
	}
	CloseHandle(this->_cachedHandle);

	HANDLE hProcess = GTOpenProcess(this->GetPID(), accessRight|_maxRight);
	if (hProcess == NULL) {
		return NULL;
	}

	_maxRight = (accessRight | _maxRight);
	this->_cachedHandle = hProcess;
	/*if (accessRight == this->_maxRight) {
		return this->_cachedHandle;
	}
	if (this->_cachedHandle != NULL) {
		CloseHandle(this->_cachedHandle);
	}
	HANDLE hProcess = GTOpenProcess(this->GetPID(), accessRight);
	if (hProcess == NULL) {
		this->_maxRight = 0;
		return NULL;
	}
	this->_cachedHandle = hProcess;
	this->_maxRight = accessRight;*/
	return this->_cachedHandle;
}

LSA_HANDLE GetPolicyHandle() {
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	TCHAR* SystemName = NULL;
	//USHORT SystemNameLength;
	//LSA_UNICODE_STRING lusSystemName;
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
	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetNativeProc("NtSuspendProcess");
	if (pfnNtSuspendProcess == NULL) {
		return GetLastError();
	}
	pfnNtSuspendProcess(GetCachedHandle(PROCESS_SUSPEND_RESUME));
	return 0;
}

DWORD Process::ResumeProcess() {
	NtSuspendProcess pfnNtResumeProcess = (NtResumeProcess)GetNativeProc("NtResumeProcess");
	pfnNtResumeProcess(GetCachedHandle(PROCESS_SUSPEND_RESUME));
	return 0;
}

DWORD Process::SetExtendedBasicInfo() {
	if (this->pExtendedBasicInfo == NULL) {
		this->pExtendedBasicInfo = (PROCESS_EXTENDED_BASIC_INFORMATION*)LocalAlloc(GPTR,sizeof(PROCESS_EXTENDED_BASIC_INFORMATION));
		if (this->pExtendedBasicInfo == NULL) {
			return GetLastError();
		}
	}
	pNtQueryInformationProcess NtQueryInfomationProcess;
	NtQueryInfomationProcess = (pNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	if (NtQueryInfomationProcess == NULL) {
		return GetLastError();
	}
	DWORD length = 0;
	DWORD status = NtQueryInfomationProcess(GetCachedHandle(PROCESS_QUERY_INFORMATION), ProcessBasicInformation, this->pExtendedBasicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), &length);
	if (!NT_SUCCESS(status)) {
		return NtStatusHandler(status);
	}

	return NtStatusHandler(status);
}

HANDLE Process::GetDupObject(HANDLE hObject) {
	pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetNativeProc("NtDuplicateObject");
	HANDLE object = NULL;
	auto status = NtDuplicateObject(
		this->GetCachedHandle(0),
		hObject,
		GetCurrentProcess(),
		&object,
		0,
		0,
		0
	);
	SetLastError(NtStatusHandler(status));
	if (status != 0) {
		return NULL;
	}
	return object;
}

VOID Process::CloseObject(HANDLE hObject) {
	if (hObject == NULL || hObject == INVALID_HANDLE_VALUE) {
		return;
	}

	CloseHandle(hObject);
}

DWORD Process::SetProcessUserName() {
	SetLastError(ERROR_SUCCESS);
	DWORD res = 0;
	LSA_HANDLE policyHandle;
	HANDLE hProcess = GTOpenProcess(processId, PROCESS_QUERY_INFORMATION);
	if (hProcess == NULL) {
		LOG_DEBUG_REASON( L"Error in GTOpenProcess");
		return GetLastError();
	}
	HANDLE processToken;
	//DWORD status;
	
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &processToken)) {
		LOG_DEBUG_REASON( L"Can not Call OpenProcessToken");
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
		LOG_DEBUG_REASON( L"Error Happen in GetTokenInformation");
		return GetLastError();
	}
	
	policyHandle = GetPolicyHandle();
	if (policyHandle == NULL) {
		//FAILS TO GET POLICY HANDLE
		LOG_DEBUG_REASON( L"Error Happen in GetPolicyHandle");
		return GetLastError();
	}

	if (processToken == NULL) {
		return GetLastError();
	}
	
	PSID sids[1];
	if (pTokenUser == NULL) {
		return GetLastError();
	}
	sids[0] = pTokenUser->User.Sid;
	PLSA_TRANSLATED_NAME names = NULL;
	PLSA_REFERENCED_DOMAIN_LIST referencedNames = NULL;
	//LPTSTR Name;
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
	HANDLE processToken = NULL;
	HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION);
	if (hProcess == NULL) {
		hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	}
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &processToken)) {
		LOG_DEBUG_REASON(L"Error OpenProcessToken");
		return GetLastError();
	}

	if (!GetTokenInformation(processToken, TokenGroups, securityState->groups, sizeof(TOKEN_GROUPS), &dwTokenGroup)) {
		status = GetLastError();
	}

	if (status == ERROR_INSUFFICIENT_BUFFER) {
		this->securityState->groups = (PTOKEN_GROUPS)realloc(securityState->groups, dwTokenGroup);
		if (this->securityState->groups == NULL) {
			LOG_DEBUG_REASON(L"Can not alloc TOKEN_GROUPS");
			return GetLastError();
		}
		
		if (!GetTokenInformation(processToken, TokenGroups, securityState->groups, dwTokenGroup, &dwTokenGroup)) {
			status = GetLastError();
			LOG_DEBUG_REASON( L"Something occurs in GetTokenInformation for TOKEN_GROUPS");
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
			LOG_DEBUG_REASON(L"Can not alloc TOKEN_GROUPS_AND_PRIVILEGES");
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenGroupsAndPrivileges, securityState->groupsWithPrivileges, dwTokenGroupsAndPrivileges, &dwTokenGroupsAndPrivileges)) {
			status = GetLastError();
			LOG_DEBUG_REASON( L"Something occurs in GetTokenInformation for TokenGroupsAndPrivileges");
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
			LOG_DEBUG_REASON(L"Can not alloc TOKEN_PRIVILEGES");
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenPrivileges, securityState->privileges, dwPrivileges, &dwPrivileges)) {
			status = GetLastError();
			LOG_DEBUG_REASON( L"Something occurs in GetTokenInformation for TokenPrivileges");
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
			LOG_DEBUG_REASON(L"Can not alloc TOKEN_MANDATORY_LABEL");
			return GetLastError();
		}

		if (!GetTokenInformation(processToken, TokenIntegrityLevel, securityState->integrity, dwTokenMandatoryLabel, &dwTokenMandatoryLabel)) {
			status = GetLastError();
			LOG_DEBUG_REASON( L"Something occurs in GetTokenInformation for TokenIntegrityLevel");
		}
	}
	return 0;
}

void Process::ChangeProcessPriority(Priority priority) {
	HANDLE hProcess = GetCachedHandle(PROCESS_SET_INFORMATION);
	if (!SetPriorityClass(hProcess, priority)) {

	}
}

Priority Process::GetPriority() {
	return GetPriorityClass(GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION));
}

Affinity Process::GetAffinity() {
	DWORD_PTR affinity;
	DWORD_PTR systemAffinity;
	if (!GetProcessAffinityMask(GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION), &affinity, &systemAffinity)) {

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
	if (this->latestCpuState == NULL) {
		//error when alloc CPUState struct
	}

	HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	
	if (hProcess == NULL) {
		return GetLastError();
	}
	if (cpuState != NULL && latestCpuState != NULL)
		*cpuState = *latestCpuState;
	if (!GetProcessTimes(hProcess, &latestCpuState->createTime, &latestCpuState->exitTime, &latestCpuState->kernelTime, &latestCpuState->userTime)) {
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
		hProcess,
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
	SetLastError(0);
	NTSTATUS status;
	ULONG returnLength = 0;
	ULONG attempts = 0;
	HANDLE hProcess = GetCachedHandle(PROCESS_ALL_ACCESS);
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
	status = NtStatusHandler(status);
	SetLastError(status);
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
	HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION);
	if (hProcess == NULL) {
		hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	}

	//Get cmdline of process
	PUNICODE_STRING123 cmdline = (PUNICODE_STRING123)LocalAlloc(GPTR, 1000);
	DWORD size = 0;
	pfnNtQueryInformationProcess NtQueryInformation = (pfnNtQueryInformationProcess)GetNativeProc("NtQueryInformationProcess");
	do {
		if (NtQueryInformation != NULL) {
			NTSTATUS status = NtQueryInformation(hProcess, ProcessCommandLineInformation, cmdline, 1000, &size);
			if (NtStatusHandler(status) == ERROR_BAD_LENGTH) {
				cmdline = (PUNICODE_STRING123)LocalReAlloc(cmdline, size+30, GPTR | GMEM_MOVEABLE);
				NTSTATUS status = NtQueryInformation(hProcess, ProcessCommandLineInformation, cmdline, size+30, &size);
				if (NtStatusHandler(status) == ERROR_SUCCESS) {
					if (cmdline->Buffer == NULL) {
						break;
					}
					imageState->cmdline = cmdline->Buffer;
					break;
				}
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
		HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION);
		if (hProcess == NULL) {
			hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
		}
		NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessVmCounters, &counters2, sizeof(VM_COUNTERS_EX2), &size);
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
	HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION);
	if (hProcess == NULL) {
		hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	}
	if (!GetProcessIoCounters(hProcess, &ioCounters)) {
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
	NTSTATUS status = NtQueryInformationProcess(GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION), ProcessIoPriority, &ioPriority, sizeof(IO_PRIORITY_HINT), &size);
	if (status != 0) {
		return NtStatusHandler(status);
	}
	this->ioState->priority = ioPriority;
	return NtStatusHandler(status);
}

BOOL Process::CreateDump(LPWSTR filename, MINIDUMP_TYPE dumpType) {
	HANDLE hProcess = GetCachedHandle(PROCESS_VM_READ);
	if (hProcess == NULL) {
		LOG_DEBUG_REASON( L"Can open process in CreateDump");
		return 0;
	}
	HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
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

GTWString Process::UserName() {
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

std::set<std::pair<GTWString, GTWString>> Process::GetLoadedFiles() {
	std::set<std::pair<GTWString, GTWString>> files;
	DWORD size;
	WCHAR path[1024];
	DWORD status = 0;

	auto handles = this->GetHandlesState();
	if (handles == NULL) {
		LOG_DEBUG_REASON("Process::GetLoadedFiles()");
		return files;
	}

	if (handles->handles == NULL) {
		LOG_DEBUG_REASON("Process::GetLoadedFiles() handles->handles");
		return files;
	}
	auto count = handles->handles->NumberOfHandles;
	
	for (int i = 0; i < count; i++) {
		WCHAR path[4096] = { 0 };
		auto handle = handles->handles->Handles[i].HandleValue;
		pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetNativeProc("NtDuplicateObject");
		HANDLE object = NULL;
		NtDuplicateObject(
			this->GetCachedHandle(PROCESS_DUP_HANDLE),
			handle,
			GetCurrentProcess(),
			&object,
			0,
			0,
			0
		);
		
		auto t_name = ObjectInfo::GetTypeName(object);
		if (_wcsicmp(t_name.c_str(), L"File") == 0 || _wcsicmp(t_name.c_str(), L"Directory") == 0) {
			WCHAR filePath[MAX_PATH];
			auto a = GetFileType(object);
			if (a == FILE_TYPE_PIPE || a == FILE_TYPE_CHAR) {
				CloseHandle(object);
				continue;
			}
			status = GetFinalPathNameByHandleW(object, path, 4096, FILE_NAME_NORMALIZED);
			if (status != 0) {
				continue;
			}
			files.insert(std::pair(t_name,path));
		}

		CloseHandle(object);
	}

	return files;
}

std::vector<LoadedDll> Process::GetLoadedDlls() {
	std::vector<LoadedDll> dlls;
	DWORD size;
	WCHAR path[1024];
	HMODULE _tmp;
	//auto hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION |PROCESS_VM_READ);
	auto hProcess = GetCachedHandle(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	if (hProcess == NULL) {
		LOG_DEBUG_REASON( L"Error OpenProcess");
		return dlls;
	}
	EnumProcessModules(hProcess, &_tmp, 0, &size);
	if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_SUCCESS) {
		LOG_DEBUG_REASON( L"Error EnumProcessModules");
		return dlls;
	}

	HMODULE* modules = (HMODULE*)LocalAlloc(GPTR,size);
	if (modules == NULL) {
		LOG_DEBUG_REASON( L"Error LocalAlloc");
		return dlls;
	}
	
	if (!EnumProcessModules(hProcess, modules, size, &size)) {
		LOG_DEBUG_REASON( L"Error EnumProcessModules");
		LocalFree(modules);
		return dlls;
	}

	DWORD length = size / sizeof(HMODULE);
	for (DWORD i = 0; i < length; i++) {
		LoadedDll dll(modules[i]);
		GetModuleFileNameExW(hProcess, modules[i], path, 1024);
		dll.SetPath(path);
		dlls.push_back(dll);
	}

	LocalFree(modules);
	return dlls;
}

std::map<DWORD, GTWString> Process::_pidProcessNameMap;
GTWString Process::GetProcessName() {
	if (this == NULL) {
		return L"";
	}
	if (this->processName.size() != 0) {
		return this->processName;
	}

	if (_pidProcessNameMap.count(this->processId) > 0) {
		return this->_pidProcessNameMap[this->processId];
	}
	else {
		HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
		PROCESSENTRY32W pe32;

		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			return L"";
		}

		pe32.dwSize = sizeof(PROCESSENTRY32W);

		if (!Process32FirstW(hProcessSnap, &pe32)) {
			CloseHandle(hProcessSnap);
			return L"";
		}
		do {
			PID pid = pe32.th32ProcessID;
			PID parentPid = pe32.th32ParentProcessID;
			if (_pidProcessNameMap.count(pid) == 0) {
				_pidProcessNameMap[pid] = pe32.szExeFile;
			}
		} while (Process32NextW(hProcessSnap, &pe32));
		CloseHandle(hProcessSnap);
	}

	if (_pidProcessNameMap.count(this->processId) > 0) {
		return this->_pidProcessNameMap[this->processId];
	}
	return L"";
}

CPUState* Process::GetLastestCPUState() {
	return this->latestCpuState;
}

DWORD Process::ReadMemoryFromAddress(PVOID address, PBYTE data,size_t size) {
	DWORD status = 0;
	HANDLE hProcess = GetCachedHandle(PROCESS_VM_READ);
	if (hProcess == NULL) {
		LOG_DEBUG_REASON(L"Access denied to process memory");
		return GetLastError();
	}
	if (!ReadProcessMemory(hProcess, address, data, size, NULL)) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			LOG_DEBUG_REASON(L"Access denied to process memory");
		}
		else {
			LOG_DEBUG_REASON(L"Error ReadProcessMemory");
		}
	}
	status = GetLastError();
	return status;
}

DWORD Process::WriteMemoryToAddress(PVOID address, PBYTE inData, size_t size) {
	DWORD status = 0;
	SIZE_T writeBytes = 0;
	HANDLE hProcess = GetCachedHandle(PROCESS_ALL_ACCESS);
	if (hProcess == NULL) {
		LOG_DEBUG_REASON(L"Access denied to process memory");
		return GetLastError();
	}
	if (!WriteProcessMemory(hProcess, address, inData, size, &writeBytes)) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			LOG_DEBUG_REASON(L"Access denied to process memory");
		}
		else {
			LOG_DEBUG_REASON(L"Error WriteProcessMemory");
		}
	}
	return status;
}

Thread::Thread(TID tid) {
	this->threadId = tid;
}

Thread::Thread(PSYSTEM_THREAD_INFORMATION pInfo) {
	this->threadId = (TID)reinterpret_cast<size_t>(pInfo->ClientId.UniqueThread);
	this->processId = (PID)reinterpret_cast<size_t>(pInfo->ClientId.UniqueProcess);
}
Thread::Thread(DWORD pid, DWORD tid) {
	this->processId = pid;
	this->threadId = tid;
}
Thread::~Thread() {

}

THREAD_BASIC_INFORMATION* Thread::GetBasicInfo() {
	auto code = this->SetBasicInfo();
	if (code != ERROR_SUCCESS) {
		return NULL;
	}
	return &this->basicInfo;
}

KERNEL_USER_TIMES* Thread::GetKernelUserTimes() {
	auto code = this->SetKernelUserTime();
	if (code != ERROR_SUCCESS) {
		return NULL;
	}
	return &this->kernelUserTime;
}

DWORD Thread::GetProcessId() {
	if (this->processId != 0) {
		return this->processId;
	}
	HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, this->threadId);
	if (hThread == NULL) {
		return 0;
	}
	this->processId = GetProcessIdOfThread(hThread);
	CloseHandle(hThread);
	return this->processId;
}

std::vector<Thread> Thread::GetThreadsByPId(DWORD pid) {
	std::vector<Thread> result;
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {
					if (te.th32OwnerProcessID == pid) {
						result.push_back(Thread(pid,te.th32ThreadID));
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	return result;
}

DWORD Thread::SetBasicInfo() {
	SetLastError(0);
	pNtQueryInformationThread NtQueryInformation = (pNtQueryInformationThread)GetNativeProc("NtQueryInformationThread");
	if (NtQueryInformation == NULL) {
		return GetLastError();
	}
	auto tid = (DWORD)this->threadId;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, false, (DWORD)tid);
	if (hThread == NULL) {
		return GetLastError();
	}
	ULONG size = 0;
	NTSTATUS status = NtQueryInformation(hThread, ThreadBasicInformation, &this->basicInfo, sizeof(THREAD_BASIC_INFORMATION), &size);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}
cleanup:
	CloseHandle(hThread);
	return 0;
}

DWORD Thread::SetKernelUserTime() {
	SetLastError(0);
	pNtQueryInformationThread NtQueryInformation = (pNtQueryInformationThread)GetNativeProc("NtQueryInformationThread");
	if (NtQueryInformation == NULL) {
		return GetLastError();
	}
	auto tid = this->threadId;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, false, tid);
	if (hThread == NULL) {
		return GetLastError();
	}
	ULONG size = 0;
	NTSTATUS status = NtQueryInformation(hThread, ThreadTimes, &this->kernelUserTime, sizeof(this->kernelUserTime), &size);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}
cleanup:
	CloseHandle(hThread);
	return 0;
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
		LOG_DEBUG_REASON(L"Can not open thread in Thread::Terminate");
		return;
	}
	if (!TerminateThread(hThread, 0)) {
		//error when terminate thread
		LOG_DEBUG_REASON(L"Can not terminate the thread");
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
	return ProcessManager::_mgr;
}

std::vector<UINT32> ProcessManager::GetPids() {
	std::vector<UINT32> result;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return result;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return result;
	}

	//For keep the orignal Process object that existed before this function is called so delete the processes
	//that not exist anymore,new the processes that not exist before this function is called.
	std::set<PID> newUpdatePids;
	do {
		PID pid = pe32.th32ProcessID;
		result.push_back(pid);
	} while (Process32NextW(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return result;
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
	PROCESSENTRY32W pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {
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
			processesMap[pid]->processName = pe32.szExeFile;

			processesMap[pid]->InitProcessStaticState();
			//processesMap[pid]->GetCPUState();
		}
		processesMap[pid]->UpdateInfo();
	} while (Process32NextW(hProcessSnap, &pe32));

	for (auto oldPid : this->lastUpdatePids) {
		if (newUpdatePids.count(oldPid) == 0) {
			delete processesMap[oldPid];
			processesMap.erase(oldPid);
		}
	}

	this->lastUpdatePids = newUpdatePids;
	CloseHandle(hProcessSnap);
	return TRUE;
}

std::map<PID, GTWString> ProcessManager::GetProcesses_Light() {
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W pe32;
	std::map<PID, GTWString> ret;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return ret;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return ret;
	}

	do {
		PID pid = pe32.th32ProcessID;
		ret[pid] = pe32.szExeFile;
	} while (Process32NextW(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return ret;
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
		PID pid = (DWORD)reinterpret_cast<size_t>(pCurProcess->UniqueProcessId);
		for (DWORD i = 0; i < pCurProcess->NumberOfThreads; i++) {
			threadsMap[pid].push_back(new Thread(&pCurProcess->Threads[i]));
		}
		pCurProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurProcess + pCurProcess->NextEntryOffset);
	}
	LocalFree(pProcessesInfo);
	return 0;
}

std::map<PID, Process*> ProcessManager::GetProcesses() {
	return std::map<PID, Process*>();
}

std::vector<Thread*>* ProcessManager::GetThreadsByPID(PID pid) {
	return &this->threadsMap[pid];
}

void ProcessManager::UpdateInfo() {
	this->SetAllProcesses();
}

bool _ImageState::IsSigned() {
	if (this->filePath.size() == 0) {
		return true;
	}
	this->info = VerifyEmbeddedSignature(this->filePath.c_str());
	if (info->isSignature) {
		return true;
	}
	return false;
}

GTWString _ImageState::GetSignInfo() {
	return this->info->info;
}

_ImageState::~_ImageState() {
	if (this->info != NULL) {
		delete this->info;
	}
}

HMODULE LoadedDll::GetModule() {
	return hModule;
}

void LoadedDll::SetPath(LPWSTR path) {
	this->path = path;
}

GTWString& LoadedDll::GetPath() {
	return this->path;
}

LoadedDll::LoadedDll(HMODULE hModule) {
	this->hModule = hModule;
}

Segment::Segment(PMEMORY_BASIC_INFORMATION info) {
	this->baseAddress = (UINT64)info->BaseAddress;
	this->allocationBase = (UINT64)info->AllocationBase;
	this->allocationProtect = (DWORD)info->AllocationProtect;
	this->regionSize = info->RegionSize;
	this->state = info->State;
	this->protect = info->Protect;
	this->type = info->Type;
}

DWORD Segment::GetType() {
	return this->type;
}

DWORD Segment::GetProtect() {
	return this->protect;
}


UINT64 Segment::GetAllocationBase()
{
	return this->allocationBase;
}

UINT64 Segment::GetBaseAddress()
{
	return this->baseAddress;
}

DWORD Segment::GetAllocationProtect() {
	return this->allocationProtect;
}

UINT64 Segment::GetRegionSize()
{
	return UINT64();
}

GTWString Segment::GetStateAsString() {
	std::vector<GTWString> result;
	if ((this->state | MEM_COMMIT) != 0) {
		result.push_back(L"MEM_COMMIT");
	}
	if ((this->state | MEM_FREE) != 0) {
		result.push_back(L"MEM_FREE");
	}
	if ((this->state | MEM_RESERVE) != 0) {
		result.push_back(L"MEM_RESERVE");
	}
	return StringUtils::StringsJoin(result, L"|");
}

DWORD Segment::GetState()
{
	return this->state;
}


GTWString Segment::GetTypeAsString() {
	std::vector<GTWString> result;
	if ((this->type | MEM_IMAGE) != 0) {
		result.push_back(L"MEM_IMAGE");
	}

	if ((this->type | MEM_MAPPED) != 0) {
		result.push_back(L"MEM_MAPPED");
	}

	if ((this->type | MEM_PRIVATE) != 0) {
		result.push_back(L"MEM_RPIVATE");
	}
	return StringUtils::StringsJoin(result, L"|");
}

BOOL Process::IsDead() {
	HANDLE hProcess = GetCachedHandle(PROCESS_QUERY_LIMITED_INFORMATION);
	DWORD code = 0;
	GetExitCodeProcess(
		hProcess,
		&code
	);

	if (code == STILL_ACTIVE) {
		return FALSE;
	}
	return TRUE;
}
