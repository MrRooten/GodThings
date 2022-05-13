#pragma once
#ifndef _NATIVE_MODULES_H
#define _NATIVE_MODULES_H
#include "Module.h"
class ProcessModule : public NativeModule {
public:
	ProcessModule();
	ResultSet* ModuleRun();
};

class ListTestModule : public NativeModule {
public:
	ListTestModule();
	ResultSet* ModuleRun();
};

class ServiceModule : public NativeModule {
public:
	ServiceModule();
	ResultSet* ModuleRun();
};

class StartupModule : public NativeModule {
public:
	StartupModule();
	ResultSet* ModuleRun();
};

class FilesRelateOpenCommandsModule : public NativeModule {
public:
	FilesRelateOpenCommandsModule();
	ResultSet* ModuleRun();
};

class NetworkModule : public NativeModule {
public:
	NetworkModule();
	ResultSet* ModuleRun();
};

class Rundll32Backdoor : public NativeModule {
public:
	Rundll32Backdoor();
	ResultSet* ModuleRun();
};

class ShadowAccount : public NativeModule {
public:
	ShadowAccount();
	ResultSet* ModuleRun();
};

class UnsignedRunningProcess : public NativeModule {
public:
	UnsignedRunningProcess();
	ResultSet* ModuleRun();
};
#endif