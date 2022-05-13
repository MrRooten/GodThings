#include "Service.h"

DWORD Srv::Start() {
	return 0;
}

Srv::~Srv() {
	if (this->pDelayedAutoStartInfo != NULL) {
		GlobalFree(this->pDelayedAutoStartInfo);
		this->pDelayedAutoStartInfo = NULL;
	}

	if (this->pDescription != NULL) {
		GlobalFree(this->pDescription);
		this->pDescription = NULL;
	}

	if (this->pFailureActions != NULL) {
		GlobalFree(this->pFailureActions);
		this->pFailureActions = NULL;
	}

	if (this->pRequiredPrivilegesInfo != NULL) {
		GlobalFree(this->pRequiredPrivilegesInfo);
		this->pRequiredPrivilegesInfo = NULL;
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
	if (this->pDescription == NULL) {
		this->pDescription = (LPSERVICE_DESCRIPTIONW)GlobalAlloc(GPTR, sizeof SERVICE_DESCRIPTIONW);
		if (this->pDescription == NULL) {
			return GetLastError();
		}
	}
	else {
		ZeroMemory(this->pDescription, sizeof LPSERVICE_DESCRIPTIONW);
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
		(LPBYTE)this->pDescription,
		sizeof SERVICE_DESCRIPTIONW,
		&dwSize
	)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			this->pDescription = (LPSERVICE_DESCRIPTIONW)GlobalReAlloc(this->pDescription, dwSize, GMEM_MOVEABLE);
			if (!QueryServiceConfig2W(
				hService,
				SERVICE_CONFIG_DESCRIPTION,
				(LPBYTE)this->pDescription,
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
		Logln(ERROR_LEVEL, L"[%s:%s:%d]:EnumServiceStatusW Fails:%d", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError());
		this->error = GetLastError();
	}
	printf("%d %d\n", cbSize/sizeof(ENUM_SERVICE_STATUSW), cbSize);

	for (int i = 0; i < numService; i++) {
		Srv* service = new Srv();
		if (service == NULL) {
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:Can not alloc space for service", __FILEW__, __FUNCTIONW__, __LINE__);
			continue;
		}
		service->serviceName = services[i].lpServiceName;
		service->displayName = services[i].lpDisplayName;
		service->serviceStatus = services[i].ServiceStatus;
		service->pSrvManager = this;
		service->SetRequirePrivilegesInfo();
		service->SetDescription();
		service->SetConfig();
		service->SetFailureActions();
		this->services.push_back(service);
	}
	GlobalFree(services);
	return 0;
}

ServiceManager::~ServiceManager() {
	for (auto service : this->services) {
		delete service;
	}
}

