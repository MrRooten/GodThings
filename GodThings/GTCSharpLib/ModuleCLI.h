#pragma once
#pragma managed
#include "Module.h"
using namespace System;
using namespace System::Collections;

namespace GodAgent {
	public ref class ResultSetCLI {
	public:
		Hashtable^ dataSet = gcnew Hashtable();
		ResultSetCLI(ResultSet* resultSet);
		Hashtable^ GetDataSet();
	};
	public ref class ModuleCLI {
	public:
		Module* _module;
		String^ Name;
		String^ Type;
		String^ Class;
		String^ Path;
		String^ Description;

		virtual ResultSetCLI^ ModuleRun() = 0;
	};

	public ref class NativeModuleCLI : public ModuleCLI {
	public:
		NativeModuleCLI(NativeModule* ntModule);
		ResultSetCLI^ ModuleRun() override;
	};

	public ref class PythonModuleCLI : public ModuleCLI {
	public:
		PythonModuleCLI(PythonModule* pyModule);
		ResultSetCLI^ ModuleRun() override;
	};

	public ref class ModuleMgrCLI {
	public:
		ArrayList^ _moduleList;
		ModuleMgrCLI();
		ArrayList^ GetModuleList();
	};

}