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
class SchduleTask {
	std::wstring path;
	std::wstring name;
	SYSTEMTIME start_time;
	SYSTEMTIME end_time;
	DWORD count;
	PSYSTEMTIME run_times;
	TASK_STATE taskState;
	IRegisteredTask* _task;
	GTWString def_xml;
public:
	SchduleTask(IRegisteredTask* task);
	std::wstring& getPath();
	std::wstring& getName();
	GTTime GetStartTime();
	GTTime GetEndTime();
	std::wstring GetState();

};


class SchduleTaskMgr {
	HRESULT hr1;
	HRESULT hr2;
	ITaskFolder* pRootFolder;
public:
	static SchduleTaskMgr* _single;
	static SchduleTaskMgr* GetMgr();
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