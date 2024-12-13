#pragma once
#include "Module.h"

class LastShutdown : public NativeModule {
public:
	LastShutdown();
	ResultSet* ModuleRun();
};

class BAMParse : public NativeModule {
public:
	BAMParse();
	ResultSet* ModuleRun();
};

class JumpListData : public NativeModule {
public:
	JumpListData();
	ResultSet* ModuleRun();
};

class ListSSP : public NativeModule {
public:
	ListSSP();
	ResultSet* ModuleRun();
};

class RDPSessions : public NativeModule {
public:
	RDPSessions();
	ResultSet* ModuleRun();
};

class RDPClientSess : public NativeModule {
public:
	RDPClientSess();
	ResultSet* ModuleRun();
};

class LoadedFiles : public NativeModule {
public:
	LoadedFiles();
	ResultSet* ModuleRun();
};

class File : public NativeModule {
public:
	File();
	ResultSet* ModuleRun();
};

class ProcessHandle : public NativeModule {
public:
	ProcessHandle();
	ResultSet* ModuleRun();
};

class ProcessTree : public NativeModule {
public:
	ProcessTree();
	ResultSet* ModuleRun();
};

class LocalAccountTokenFilterPolicyBackDoor : public NativeModule {
public:
	LocalAccountTokenFilterPolicyBackDoor();
	ResultSet* ModuleRun();
};

class StaticInfo : public NativeModule {
public:
	StaticInfo();
	ResultSet* ModuleRun();
};

class NetInterfaces : public NativeModule {
public:
	NetInterfaces();
	ResultSet* ModuleRun();
};

class WmiSchduleTask : public NativeModule {
public:
	WmiSchduleTask();
	ResultSet* ModuleRun();
};

class WmiDrivers : public NativeModule {
public:
	WmiDrivers();
	ResultSet* ModuleRun();
};

class USNRecord : public NativeModule {
public:
	USNRecord();
	ResultSet* ModuleRun();
};

class ServiceStartLog : public NativeModule {
public:
	ServiceStartLog();
	ResultSet* ModuleRun();
};