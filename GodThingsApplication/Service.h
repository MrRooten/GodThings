#pragma once
#include "public.h"
#include <string>
#include <vector>
#include "utils.h"

class ServiceManager;
class Srv {
	std::wstring serviceName;
	std::wstring displayName;
	std::wstring filePath;
	std::wstring userName;
	std::wstring SID;
	SERVICE_STATUS serviceStatus;
	std::vector<Srv*> dependentServices;
	ServiceManager* pSrvManager = NULL;
	
	DWORD SetConfig();

	LPSERVICE_DELAYED_AUTO_START_INFO pDelayedAutoStartInfo = NULL;
	DWORD SetDelayedAutoStartInfo();

	std::wstring description;
	DWORD SetDescription();

	LPSERVICE_FAILURE_ACTIONSW pFailureActions;
	DWORD SetFailureActions();

	
	LPSERVICE_FAILURE_ACTIONS_FLAG pFailureActionsFlag;
	DWORD SetFailureActionsFlag();

	LPSERVICE_PREFERRED_NODE_INFO pPreferredNodeInfo;
	DWORD SetPreferredNodeInfo();

	LPSERVICE_PRESHUTDOWN_INFO pPreshutdownInfo;
	DWORD SetPreshutdownInfo();

	LPSERVICE_SID_INFO pSIDInfo;
	DWORD SetSIDInfo();

	LPSERVICE_REQUIRED_PRIVILEGES_INFOW pRequiredPrivilegesInfo;
	DWORD SetRequirePrivilegesInfo();

	PSERVICE_TRIGGER_INFO pTriggerInfo;
	DWORD SetTriggerInfo();

	PSERVICE_LAUNCH_PROTECTED_INFO pLaunchProtectedInfo;
	DWORD SetLaunchProtectedInfo();

	DWORD SetDependentServices();

	DWORD SetSrvRegKey();

	LPSERVICE_STATUS_PROCESS pStatusProcess = NULL;
	DWORD SetStatusProcess();
public:
	
	HKEY srvRegKey;
	~Srv();

	DWORD Start();

	DWORD Stop();

	DWORD DeleteService();

	std::wstring GetType();

	std::wstring GetStartType();

	std::wstring& GetDescription();

	VOID SetServiceName(LPCWSTR serviceName);

	VOID SetDisplayName(LPCWSTR displayName);

	VOID SetFilePath(LPCWSTR filePath);

	VOID SetUserName(LPCWSTR userName);
	
	VOID SetServiceStatus(SERVICE_STATUS status);

	VOID SetSrvManager(ServiceManager* mgr);

	std::wstring GetServiceStatus();

	std::wstring& GetServiceName();

	std::wstring& GetDisplayName();

	std::wstring& GetFilePath();

	std::wstring& GetUserName();

	std::wstring& GetSID();

	LPWSTR GetFailureActionCommand();

	DWORD GetOwningPid();
};


class ServiceManager {
private:
	
public:
	SC_HANDLE hSCManger;
	DWORD error;
	std::vector<Srv*> services;
	ServiceManager();
	~ServiceManager();
	DWORD SetAllServices();
	DWORD CreateService(LPCWSTR name, LPCWSTR displayName, DWORD type, DWORD startType, DWORD errorControl, LPCWSTR binaryPath);
};