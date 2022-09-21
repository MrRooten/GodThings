#pragma once
#include "public.h"
#include <map>
#include <string>
class DeviceInfo {

};

class DriverInfo {
	std::wstring driverName;
public:
	DriverInfo();
	DriverInfo(wchar_t* driverName);
};

using DriverMap = std::map<std::wstring, DriverInfo*>;
class DriverMgr {
	DWORD SetDrivers();
	static DriverMgr* _mgr;
public:
	DriverMap _driverMap;
	static DriverMgr* GetMgr();
	DriverMap& GetDriverMap();
	DriverMgr();
	DriverInfo* Next();
	~DriverMgr();
};

