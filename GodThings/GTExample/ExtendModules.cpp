#include "ExtendModules.h"
#include "RegistryUtils.h"
#include "utils.h"
LastShutdown::LastShutdown() {
	this->Name = L"LastShutdown";
	this->Path = L"System";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get Last shutdown time";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* LastShutdown::ModuleRun() {
	ResultSet* result = new ResultSet();
	auto v = RegistryUtils::GetValueStatic(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Windows", L"ShutdownTime");
	auto t = get_u64l(v.c_str());
	FILETIME ft;
	ft.dwLowDateTime = t && 0xffffffff;
	ft.dwHighDateTime = t >> 32;
	GTTime gTime(ft);
	result->PushDictOrdered("LastShutdown", StringUtils::ws2s(gTime.ToString()));
	result->SetType(DICT);
	return result;
}

BAMParse::BAMParse() {
	this->Name = L"BAMParse";
	this->Path = L"System";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"BAMParse";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* BAMParse::ModuleRun() {
	ResultSet* result = new ResultSet();
	GTWString path = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
	RegistryUtils utils(path);
	auto keys = utils.ListSubKeys();
	for (auto& key : keys) {
		auto target = path + L"\\" + key;
		RegistryUtils sidRegistry(target);
		auto names = sidRegistry.ListValueNames();
		for (auto& name : names) {
			RegistryUtils _get_type(target.c_str());
			DWORD type = 0;
			auto ret = _get_type.GetValueType(name.c_str(), &type);
			if (ret != 0) {
				continue;
			}

			if (type != REG_BINARY) {
				continue;
			}
			auto v = RegistryUtils::GetValueStatic(target.c_str(), name.c_str());
			auto utc = get_u64l(v.c_str());
			auto time = GTTime::FromTimeStamp64(utc);
			result->PushDictOrdered("sid", StringUtils::ws2s(key));
			result->PushDictOrdered("exe", StringUtils::ws2s(name));
			result->PushDictOrdered("time", StringUtils::ws2s(time.ToString()));
		}
	}
	result->SetType(DICT);
	return result;
}
