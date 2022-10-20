#pragma once
#include "Module.h"

class GetUserHashes : NativeModule {
public:
	GetUserHashes();
	ResultSet* ModuleRun();
};

class AddHistorySID : NativeModule {
public:
	AddHistorySID();
	ResultSet* ModuleRun();
};

class NDTSHashDumper : NativeModule {
public:
	NDTSHashDumper();
	ResultSet* ModuleRun();
};

class GetSPN : NativeModule {
public:
	GetSPN();
	ResultSet* ModuleRun();
};

class GetDCInfo : NativeModule {
public:
	GetDCInfo();
	ResultSet* ModuleRun();
};

class PassTheHash : NativeModule {
public:
	PassTheHash();
	ResultSet* ModuleRun();
};

class ExportNTDS : NativeModule {
public:
	ExportNTDS();
	ResultSet* ModuleRun();
};

class DCSync : NativeModule {
public:
	DCSync();
	ResultSet* ModuleRun();
};

class RunCommandWithSystem : NativeModule {
public:
	RunCommandWithSystem();
	ResultSet* ModuleRun();
};

class UnconstrainedDelegation : NativeModule {
public:
	UnconstrainedDelegation();
	ResultSet* ModuleRun();
};