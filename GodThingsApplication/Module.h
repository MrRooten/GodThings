#pragma once
#ifndef _MODULE_H
#define _MODULE_H
#include "public.h"
#include <string>
#include <vector>
#include <map>
#include <future>
#include <json/json.h>
#include "PythonUtils.h"
enum ResultType {
	TEXT_STRING,
	DICT,
	ARRAY,
	BINARY,
	BASE64,
	JSON,
	NONE,
	ERROR_MESSAGE
};
class ResultSet {
private:
	std::string errorMessage;
	std::vector<std::string> _map_order;
	
public:
	ResultType type;
	std::string data;
	using Dict = std::map<std::string, std::vector<std::string>>;
	using Array = std::vector<std::string>;
	Dict dataDict;
	Array dataArray;
	std::string report;
	
	std::vector<std::string>& GetMapOrder();

	ResultSet();

	ResultSet(std::string const& data);

	ResultSet(Dict const &data);

	ResultSet(Array const &data);

	inline VOID SetType(ResultType type) {
		this->type = type;
	}

	void PushDictOrdered(std::string, std::string);

	inline VOID SetErrorMessage(const std::string& message) {
		this->type = ERROR_MESSAGE;
		this->errorMessage = message;
	}

	inline std::string GetErrorMessage() {
		return this->errorMessage;
	}

	std::string ToJsonString();

	Json::Value ToJsonObject();

	std::string ToCsvString();
};

enum RunType{
	ModuleAuto,
	ModuleNeedArgs,
	ModuleNotImplement,
	ModuleNotAuto
};

class Module {
public:
	std::wstring Name;
	std::wstring Type;
	std::wstring Class;
	std::wstring Path;
	std::wstring Description;
	RunType RunType = ModuleAuto;
#ifdef  PYTHON_ENABLE
	PyInterpreterState* state;
#endif //  PYTHON_ENABLE
	using Args = std::map<std::string, std::string>;
	Args args;
	VOID SetArgs(const Args &args);
#ifdef  PYTHON_ENABLE
	VOID SetVM(PyInterpreterState* state);
#endif //  PYTHON_ENABLE
	virtual void Initialize() = 0;
	virtual ResultSet* ModuleRun() = 0;
	Json::Value GetModuleMetaJson();
};

class PythonModule : public Module {
private:
	void _LoadMetaData();
	void Initialize();
	ResultSet* _result_set;
	std::promise<ResultSet*>* pPromise = NULL;
	std::mutex _locker;
public:
	PythonModule(std::wstring path);
#ifdef  PYTHON_ENABLE
	ResultSet* ModuleRun() override;
#endif //  PYTHON_ENABLE
	VOID SetPromise(std::promise<ResultSet*> &promise);
};

class NativeModule : public Module {
private:
	std::promise<ResultSet*>* pPromise = NULL;
public:
	virtual void Initialize();
	virtual ResultSet* ModuleRun() = 0;
	VOID SetPromise(std::promise<ResultSet*>& promise);
};



class ModuleMgr {
public:
	static ModuleMgr* ModManager;
	static ModuleMgr* GetMgr();
	std::vector<Module*> modules;
	DWORD RegisterModule(Module* mod);
	DWORD LoadModules();
	std::string GetModulesJson();
	Module* FindModuleByName(const char* modName);
	Module* FindModuleByName(const wchar_t* modName);
};

#endif