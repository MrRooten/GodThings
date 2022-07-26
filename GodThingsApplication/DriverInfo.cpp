#include "DriverInfo.h"
#include <Psapi.h>

DriverMgr* DriverMgr::_mgr = NULL;
DriverMgr::DriverMgr() {

}

DWORD DriverMgr::SetDrivers() {
    LPVOID drivers[4096];
    DWORD cbNeeded = 0;
    int cDrivers, i;
    for (auto& pair : this->_driverMap) {
        delete pair.second;
    }
    this->_driverMap.clear();
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        wchar_t szDriver[4096];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < cDrivers; i++) {
            if (GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                std::wstring dName = szDriver;
                delete _driverMap[dName];
                _driverMap[dName] = new DriverInfo(const_cast<wchar_t*>(dName.c_str()));
                
            }
        }
    }
    return GetLastError();
}

DriverMgr::~DriverMgr() {
    for (auto& pair : this->_driverMap) {
        delete pair.second;
    }
    this->_driverMap.clear();
}

DriverMap& DriverMgr::GetDriverMap() {
    this->SetDrivers();
    return _driverMap;
}

DriverMgr* DriverMgr::GetMgr() {
	if (_mgr == NULL) {
		_mgr = new DriverMgr();
	}

	return _mgr;
}

DriverInfo::DriverInfo(wchar_t* driverName) {
    this->driverName = driverName;
}
