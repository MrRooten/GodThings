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