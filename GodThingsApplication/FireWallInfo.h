#pragma once
#include "public.h"
#include "utils.h"
#include <vector>
#include <functional>
enum class FwAction{

};

enum class FwDirection {

};

class FwRule {
	GTWString name;
	GTWString description;
	GTWString appName;
	GTWString serviceName;
	GTWString protocol;
	std::vector<int> localPorts;
	std::vector<int> remotePorts;
	std::vector<GTWString> localAddresses;
	std::vector<GTWString> remoteAddresses;
	FwAction action;
	FwDirection direction;
	GTWString netInterface;
	bool enable;
public:

};

using FwCallback = std::function<bool(FwRule&)>;

class FwRuleMgr {

public:
	FwRuleMgr* GetInstance();
	void IterateFwRule(FwCallback callback);
};