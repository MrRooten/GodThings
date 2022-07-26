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
public:
	DriverMap _driverMap;
	static DriverMgr* _mgr;
	static DriverMgr* GetMgr();
	DriverMap& GetDriverMap();
	DriverMgr();
	DWORD SetDrivers();
	DriverInfo* Next();
	~DriverMgr();
};

