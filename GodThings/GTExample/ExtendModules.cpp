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
	result->PushDictOrdered("LastShutdown", StringUtils::ws2s(gTime.String()));
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
			result->PushDictOrdered("time", StringUtils::ws2s(time.String()));
		}
	}
	result->SetType(DICT);
	return result;
}

JumpListData::JumpListData() {
	this->Name = L"JumpListData";
	this->Path = L"Registry";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Registry JumpListData";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* JumpListData::ModuleRun() {
	ResultSet* result = new ResultSet();
	auto s = L"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData";
	RegistryUtils utils(s);
	auto names = utils.ListValueNames();
	for (auto& name : names) {
		auto v = RegistryUtils::GetValueStatic(s, name.c_str());
		auto s = get_u64l(v.data());
		auto exec = GTTime::FromTimeStamp64(s);
		result->PushDictOrdered("name", StringUtils::ws2s(name));
		result->PushDictOrdered("exec", StringUtils::ws2s(exec.String()));
	}
	result->SetType(DICT);
	return result;
}
#include "OtherInfo.h"
ListSSP::ListSSP() {
	this->Name = L"ListSSP";
	this->Path = L"Other";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"List Security Provider";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ListSSP::ModuleRun() {
	auto providers = SecurityProvider::ListProviders();
	for (auto& provider : providers) {
		wprintf(L"%s %s\n", provider.GetName().c_str(), provider.GetComment().c_str());
	}
	return nullptr;
}
