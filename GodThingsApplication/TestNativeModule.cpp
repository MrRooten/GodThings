#include "TestNativeModule.h"

TestModule::TestModule() {
	this->Name = L"Test";
	this->Path = L"TestPath";
	this->Type = L"Native";
	this->Class = L"Contorl";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* TestModule::ModuleRun() {
	printf("Test Module\n");
	ResultSet* result = new ResultSet();
	result->data = "Test Module Result";
	result->SetType(TEXT_STRING);
	return result;
}

