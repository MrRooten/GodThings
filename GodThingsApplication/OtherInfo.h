#pragma once
#include "public.h"
#define _WIN32_DCOM
#define SECURITY_WIN32
#include <iostream>
#include <stdio.h>
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#include <vector>
#include <functional>
#include <security.h>
#include "utils.h"
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "Secur32.lib")

class Principal {
	GTWString userId;
	GTWString logonType;
	GTWString runLevel;
public:
	void SetUserId(GTWString name);
	GTWString& GetUserId();
	void SetLogonType(GTWString logonType);
	GTWString& GetLogonType();
	void SetRunLevel(GTWString runLevel);
	GTWString& GetRunLevel();
	Principal();
};

class TaskInfo {
	GTWString Date;
	GTWString Author;
	GTWString Uri;
	std::vector<Principal> Principals;
	//GTWString RunLevel;
	//GTWString MultiInstancesPolicy;
	//GTWString DisallowStartIfOnBatteries;
	//GTWString AllowStartOnDemand;
	//GTWString Priority;
	GTWString Exec;
public:
	TaskInfo(const wchar_t* xml);
	GTWString& GetExec();
	GTWString& GetDate();
	TaskInfo();
};



class SchduleTask {
	std::wstring path;
	std::wstring name;
	SYSTEMTIME start_time;
	SYSTEMTIME end_time;
	DWORD count;
	PSYSTEMTIME run_times;
	TASK_STATE taskState;
	IRegisteredTask* _task;
	TaskInfo info;
public:
	SchduleTask(IRegisteredTask* task);
	std::wstring& getPath();
	std::wstring& getName();
	GTTime GetStartTime();
	GTTime GetEndTime();
	std::wstring GetState();
	GTWString& GetExec();
	GTWString& GetRegDate();
	~SchduleTask();
};


class SchduleTaskMgr {
	HRESULT hr1;
	HRESULT hr2;
	ITaskFolder* pRootFolder;
public:
	static SchduleTaskMgr* _single;
	static SchduleTaskMgr* GetMgr();
	static void DeleteMgr();
	SchduleTaskMgr();
	std::vector<SchduleTask> GetTasks();
	void EnumTasks(std::function<void(SchduleTask*)> callback);
	~SchduleTaskMgr();
};

class SecurityProvider {
	GTWString name;
	GTWString comment;
	unsigned long maxToken;
	unsigned short RPCID;
	unsigned long fCapabilities;
	unsigned short wVersion;
public:
	SecurityProvider(SecPkgInfoW& package);
	static std::vector<SecurityProvider> ListProviders();
	GTWString& GetName();
	GTWString& GetComment();
	ULONG GetMaxToken();
	USHORT GetRPCID();
};