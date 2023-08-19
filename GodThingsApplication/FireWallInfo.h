#pragma once
#include "public.h"
#include "utils.h"
#include <vector>
#include <functional>

#include <comutil.h>
#include <atlcomcli.h>
#include <netfw.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

class FwAction{

public:
	enum action{
		Block,
		Allow
	};
	FwAction();
	FwAction(action a);
	GTWString WString();
private:
	action a;
};

class FwDirection {
public:
	enum direction{
		In,
		Out
	};
	FwDirection();
	FwDirection(direction d);
	GTWString WString();
private:
	direction d;
};

class FwRule {
	GTWString name;
	GTWString description;
	GTWString appName;
	GTWString serviceName;
	GTWString protocol;
	GTWString localPorts;
	GTWString remotePorts;
	GTWString localAddresses;
	GTWString remoteAddresses;
	FwAction action;
	FwDirection direction;
	GTWString netInterface;
	bool enable;
public:
	FwRule();
	static FwRule* NewFwRule(INetFwRule* rule);
	GTWString& GetName();
	GTWString& GetDescription();
	GTWString& GetAppName();
	GTWString& GetServiceName();
	GTWString& GetProtocol();
	GTWString& GetLocalPorts();
	GTWString& GetRemotePorts();
	GTWString& GetLocalAddresses();
	GTWString& GetRemoteAddresses();
	FwAction GetAction();
	FwDirection GetDirection();
	GTWString& GetNetInterfaces();
	bool IsEnable();
};

using FwCallback = std::function<bool(FwRule*)>;

class FwRuleMgr {
public:
	FwRuleMgr();
	static DWORD Initialize();
	FwRuleMgr* GetInstance();
	static void IterateFwRule(FwCallback callback);
};