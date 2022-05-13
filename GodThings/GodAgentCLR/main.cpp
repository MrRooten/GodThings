#include "Process.h"
#include "PythonUtils.h"
#include "Module.h"
#include "TestNativeModule.h"
#include <stdlib.h>
#include <iostream>
#include "../../GodThingsApplication/Module.h"

using namespace System;
using namespace System::IO;


int main() {
	auto mgr = ModuleMgr::GetMgr();
	TestModule test;
	PythonModule pyTest(L"D:\\SourceCodes\\qwer");
	std::vector<PyObject*> args;
	PythonUtils::RunFunction("D:\\\\SourceCodes\\\\qwer","meta_data",args);
	wprintf(L"%d\n", mgr->modules.size());
	for (auto item : mgr->modules) {
		wprintf(L"%s\n", item->Name.c_str());
	}
}


