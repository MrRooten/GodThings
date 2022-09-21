#include "HackDetectModules.h"
#include "EvtInfo.h"
PrintNightmare::PrintNightmare() {
	this->Name = L"PrintNightmare";
	this->Path = L"Vuln";
	this->Type = L"Native";
	this->Class = L"DetectHack";
	this->Description = L"Get Process Infomation";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* PrintNightmare::ModuleRun() {
	ResultSet* result = new ResultSet();
	//Logs
	auto evtSet = EvtInfo::GetEvtSetByEventId(L"7032", L"System");
	auto evts = evtSet->GetAllEvts();
	if (evts.size() >= 0) {
		result->data = "Has PrintNighmare attach signature: 7032 logs";
		result->SetType(TEXT_STRING);
	}
	delete evtSet;
	//File
	std::wstring spool_path = L"C:\\Windows\\System32\\spool\\drivers\\x64\\3";


	//Logs for printer service


	return result;
}

