#include "Service.h"

DWORD Srv::Start() {
	return 0;
}

DWORD Srv::SetStatusProcess() {
	if (this->pStatusProcess == NULL) {
		this->pStatusProcess = (LPSERVICE_STATUS_PROCESS)LocalAlloc(GPTR, sizeof(SERVICE_STATUS_PROCESS));
		if (this->pStatusProcess == NULL) {
			return GetLastError();
		}
	}
	SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}
	DWORD ret = 0;
	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)this->pStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &ret)) {
		return GetLastError();
	}

	return GetLastError();
}

Srv::~Srv() {
	if (this->pDelayedAutoStartInfo != NULL) {
		GlobalFree(this->pDelayedAutoStartInfo);
		this->pDelayedAutoStartInfo = NULL;
	}



	if (this->pFailureActions != NULL) {
		GlobalFree(this->pFailureActions);
		this->pFailureActions = NULL;
	}

	if (this->pRequiredPrivilegesInfo != NULL) {
		GlobalFree(this->pRequiredPrivilegesInfo);
		this->pRequiredPrivilegesInfo = NULL;
	}

	if (this->pStatusProcess != NULL) {
		LocalFree(this->pStatusProcess);
		this->pStatusProcess = NULL;
	}

}
DWORD Srv::SetConfig() {
	SC_HANDLE hSCManager = NULL;
	LPQUERY_SERVICE_CONFIGW lpConfig = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}

	DWORD dwSize = 0;
	if (!QueryServiceConfigW(hService,
		NULL,
		0,
		&dwSize
	)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			lpConfig = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(GPTR, dwSize);
			if (lpConfig == NULL) {
				return GetLastError();
			}
			if (!QueryServiceConfigW(
				hService,
				lpConfig,
				dwSize,
				&dwSize
			)) {
				return GetLastError();
			}
		}
		else {
			return GetLastError();
		}
	}

	this->filePath = lpConfig->lpBinaryPathName;
	LocalFree(lpConfig);
	return 0;
}
DWORD Srv::SetDelayedAutoStartInfo() {
	if (this->pDelayedAutoStartInfo == NULL) {
		this->pDelayedAutoStartInfo = (LPSERVICE_DELAYED_AUTO_START_INFO)GlobalAlloc(GPTR, sizeof SERVICE_DELAYED_AUTO_START_INFO);
		if (this->pDelayedAutoStartInfo == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pDelayedAutoStartInfo, sizeof LPSERVICE_DELAYED_AUTO_START_INFO);
	}

	SC_HANDLE hSCManager = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}
	DWORD dwSize = 0;
	if (!QueryServiceConfig2W(
		hService,
		SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
		(LPBYTE)this->pDelayedAutoStartInfo,
		sizeof SERVICE_DELAYED_AUTO_START_INFO,
		&dwSize
	)) {

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}

DWORD Srv::SetFailureActions() {
	if (this->pFailureActions == NULL) {
		this->pFailureActions = (LPSERVICE_FAILURE_ACTIONSW)GlobalAlloc(GPTR, sizeof SERVICE_FAILURE_ACTIONSW);
		if (this->pFailureActions == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pFailureActions, sizeof LPSERVICE_FAILURE_ACTIONSW);
	}

	SC_HANDLE hSCManager = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	

	if (hSCManager == NULL) {
		return GetLastError();
	}
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}

	DWORD dwSize = 0;
	if (!QueryServiceConfig2W(
		hService,
		SERVICE_CONFIG_FAILURE_ACTIONS,
		(LPBYTE)this->pFailureActions,
		sizeof SERVICE_FAILURE_ACTIONSW,
		&dwSize
	)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			this->pFailureActions = (LPSERVICE_FAILURE_ACTIONSW)GlobalReAlloc(this->pFailureActions, dwSize, GMEM_MOVEABLE);
			if (!QueryServiceConfig2W(
				hService,
				SERVICE_CONFIG_FAILURE_ACTIONS,
				(LPBYTE)this->pFailureActions,
				dwSize,
				&dwSize
			)) {
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				return GetLastError();
			}
		}
		else {
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return GetLastError();
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}

std::wstring Srv::GetServiceStatus() {
	SC_HANDLE hSCManager = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);


	if (hSCManager == NULL) {
		return L"UNKNOWN";
	}
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return L"UNKNOWN";
	}

	if (!QueryServiceStatus(hService, &this->serviceStatus)) {
		return L"UNKNOWN";
	}
	std::wstring res;
	if (this->serviceStatus.dwCurrentState == SERVICE_CONTINUE_PENDING) {
		res = L"SERVICE_CONTINUE_PENDING";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_PAUSE_PENDING) {
		res = L"SERVICE_PAUSE_PENDING";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_PAUSED) {
		res = L"SERVICE_PAUSED";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_RUNNING) {
		res = L"SERVICE_RUNNING";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_START_PENDING) {
		res = L"SERVICE_START_PENDING";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_STOP_PENDING) {
		res = L"SERVICE_STOP_PENDING";
	}
	else if (this->serviceStatus.dwCurrentState == SERVICE_STOPPED) {
		res = L"SERVICE_STOPPED";
	}
	else {
		res = L"UNKNOWN";
	}
	return res;
}

DWORD Srv::SetDescription() {
	LPSERVICE_DESCRIPTIONW pDescription = NULL;
	if (pDescription == NULL) {
		pDescription = (LPSERVICE_DESCRIPTIONW)GlobalAlloc(GPTR, sizeof SERVICE_DESCRIPTIONW);
		if (pDescription == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(pDescription, sizeof LPSERVICE_DESCRIPTIONW);
	}

	SC_HANDLE hSCManager = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	

	if (hSCManager == NULL) {
		return GetLastError();
	}
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}

	DWORD dwSize = 0;
	if (!QueryServiceConfig2W(
		hService,
		SERVICE_CONFIG_DESCRIPTION,
		(LPBYTE)pDescription,
		sizeof SERVICE_DESCRIPTIONW,
		&dwSize
	)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			pDescription = (LPSERVICE_DESCRIPTIONW)GlobalReAlloc(pDescription, dwSize, GMEM_MOVEABLE);
			if (!QueryServiceConfig2W(
				hService,
				SERVICE_CONFIG_DESCRIPTION,
				(LPBYTE)pDescription,
				dwSize,
				&dwSize
			)) {
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				return GetLastError();
			}
		}
		else {
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return GetLastError();
		}
	}

	if (pDescription->lpDescription == NULL) {
		this->description = L"";
	}
	else {
		this->description = pDescription->lpDescription;
	}
	GlobalFree(pDescription);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}

DWORD Srv::SetRequirePrivilegesInfo() {
	if (this->pRequiredPrivilegesInfo == NULL) {
		this->pRequiredPrivilegesInfo = (LPSERVICE_REQUIRED_PRIVILEGES_INFOW)GlobalAlloc(GPTR, sizeof SERVICE_REQUIRED_PRIVILEGES_INFOW);
		if (this->pRequiredPrivilegesInfo == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pRequiredPrivilegesInfo, sizeof LPSERVICE_REQUIRED_PRIVILEGES_INFOW);
	}

	SC_HANDLE hSCManager = NULL;
	hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);


	if (hSCManager == NULL) {
		return GetLastError();
	}
	SC_HANDLE hService = OpenServiceW(hSCManager, this->serviceName.c_str(), SERVICE_QUERY_CONFIG);
	if (hService == NULL) {
		CloseServiceHandle(hSCManager);
		return GetLastError();
	}

	DWORD dwSize = 0;
	if (!QueryServiceConfig2W(
		hService,
		SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
		(LPBYTE)this->pRequiredPrivilegesInfo,
		sizeof SERVICE_REQUIRED_PRIVILEGES_INFOW,
		&dwSize
	)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			SetLastError(0);
			this->pRequiredPrivilegesInfo = (LPSERVICE_REQUIRED_PRIVILEGES_INFOW)GlobalReAlloc(this->pRequiredPrivilegesInfo, dwSize, GMEM_MOVEABLE);
			if (!QueryServiceConfig2W(
				hService,
				SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
				(LPBYTE)this->pRequiredPrivilegesInfo,
				dwSize,
				&dwSize
			)) {
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				return GetLastError();
			}
		}
		else {
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return GetLastError();
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}
std::wstring& Srv::GetDescription() {
	if (this->description.size() == 0) {
		this->SetDescription();
	}

	return this->description;
}
VOID Srv::SetServiceName(LPCWSTR serviceName) {
	this->serviceName = serviceName;
}

VOID Srv::SetDisplayName(LPCWSTR displayName) {
	this->displayName = displayName;
}

VOID Srv::SetFilePath(LPCWSTR filePath) {
	this->filePath = filePath;
}

VOID Srv::SetUserName(LPCWSTR userName) {
	this->userName = userName;
}

VOID Srv::SetServiceStatus(SERVICE_STATUS status) {
	this->serviceStatus = status;
}

VOID Srv::SetSrvManager(ServiceManager* mgr) {
	this->pSrvManager = mgr;
}

std::wstring& Srv::GetServiceName() {
	return this->serviceName;
}

std::wstring& Srv::GetDisplayName() {
	return this->displayName;
}

std::wstring& Srv::GetFilePath() {
	return this->filePath;
}

std::wstring& Srv::UserName() {
	return this->userName;
}

std::wstring& Srv::GetSID() {
	if (this->SID.size() == 0) {
		//this->SetSIDInfo();
	}

	return this->SID;
}

LPWSTR Srv::GetFailureActionCommand() {
	if (this->pFailureActions == NULL) {
		this->SetFailureActions();
	}

	return this->pFailureActions->lpCommand;
}

DWORD Srv::GetOwningPid() {
	auto ret = this->SetStatusProcess();
	if (ret != 0) {
		return -1;
	}

	return this->pStatusProcess->dwProcessId;
}



ServiceManager::ServiceManager() {
	this->hSCManger = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (this->hSCManger == INVALID_HANDLE_VALUE) {
		this->error = GetLastError();
	}
}

DWORD ServiceManager::SetAllServices() {
	DWORD cbSize;
	DWORD numService;
	if (!EnumServicesStatusW(this->hSCManger,
		SERVICE_DRIVER| SERVICE_FILE_SYSTEM_DRIVER| SERVICE_KERNEL_DRIVER| SERVICE_WIN32| SERVICE_WIN32_OWN_PROCESS| SERVICE_WIN32_SHARE_PROCESS,
		SERVICE_STATE_ALL,
		NULL,
		0,
		&cbSize,
		&numService,
		NULL
		)) {
		this->error = GetLastError();
	}
	if (this->error == ERROR_MORE_DATA) {
		SetLastError(ERROR_SUCCESS);
	}
	ENUM_SERVICE_STATUSW* services = (ENUM_SERVICE_STATUSW*)GlobalAlloc(GPTR, cbSize);
	DWORD tmp;
	if (!EnumServicesStatusW(this->hSCManger,
		SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32 | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
		SERVICE_STATE_ALL,
		services,
		cbSize,
		&tmp,
		&numService,
		NULL
	)) {
		LOG_DEBUG_REASON(L"EnumServiceStatusW Fails");
		this->error = GetLastError();
	}

	for (size_t i = 0; i < numService; i++) {
		Srv* service = new Srv();
		if (service == NULL) {
			LOG_DEBUG_REASON(L"Can not alloc space for service");
			continue;
		}
		service->SetServiceName(services[i].lpServiceName);
		service->SetDisplayName(services[i].lpDisplayName);
		service->SetServiceStatus(services[i].ServiceStatus);
		service->SetSrvManager(this);
		this->services.push_back(service);
	}
	GlobalFree(services);
	return 0;
}

DWORD ServiceManager::CreateService(LPCWSTR name, LPCWSTR displayName, DWORD type, DWORD startType, DWORD errorControl, LPCWSTR binaryPath) {
	if (this->hSCManger == NULL) {
		return -1;
	}

	SC_HANDLE srv = CreateServiceW(
		this->hSCManger,
		name,
		displayName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		binaryPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (srv == NULL) {
		return GetLastError();
	}
	return 0;
}

ServiceManager::~ServiceManager() {
	for (auto service : this->services) {
		delete service;
	}
}

