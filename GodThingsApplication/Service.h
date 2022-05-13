#pragma once
#include "public.h"
#include <string>
#include <vector>
#include "utils.h"

class ServiceManager;
class Srv {
public:
	std::wstring serviceName;
	std::wstring displayName;
	std::wstring filePath;
	std::wstring userName;
	std::wstring SID;
	SERVICE_STATUS serviceStatus;
	std::vector<Srv*> dependentServices;
	ServiceManager* pSrvManager = NULL;
	HKEY srvRegKey;
	~Srv();
	DWORD Start();
	DWORD Stop();
	DWORD DeleteService();
	std::wstring GetType();
	std::wstring GetStartType();

	DWORD SetConfig();

	LPSERVICE_DELAYED_AUTO_START_INFO pDelayedAutoStartInfo = NULL;
	DWORD SetDelayedAutoStartInfo();

	LPSERVICE_DESCRIPTIONW pDescription;
	DWORD SetDescription();

	LPSERVICE_FAILURE_ACTIONSW pFailureActions;
	DWORD SetFailureActions();

	std::wstring GetServiceStatus();
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
};