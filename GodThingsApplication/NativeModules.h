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

class DriverList : public NativeModule {
public:
	DriverList();
	ResultSet* ModuleRun();
};

class USBHistory : public NativeModule {
public:
	USBHistory();
	ResultSet* ModuleRun();
};

class PrefetchModule : public NativeModule {
public:
	PrefetchModule();
	ResultSet* ModuleRun();
};

class ListSchduleTask : public NativeModule {
public:
	ListSchduleTask();
	ResultSet* ModuleRun();
};

class SaveFiles : public NativeModule {
public:
	SaveFiles();
	ResultSet* ModuleRun();
};

class PrefetchTimeline : public NativeModule {
public:
	PrefetchTimeline();
	ResultSet* ModuleRun();
};

class DetailPrefetch : public NativeModule {
public:
	DetailPrefetch();
	ResultSet* ModuleRun();
};

class DllInjectRoughDet : public NativeModule {
public:
	DllInjectRoughDet();
	ResultSet* ModuleRun();
};

class UnsignedServices : public NativeModule {
public:
	UnsignedServices();
	ResultSet* ModuleRun();
};

class RegularBackdoorDet : public NativeModule {
public:
	RegularBackdoorDet();
	ResultSet* ModuleRun();
};

class LoopNetstat : public NativeModule {
public:
	LoopNetstat();
	ResultSet* ModuleRun();
};

class MailiousProcessDlls : public NativeModule {
public:
	MailiousProcessDlls();
	ResultSet* ModuleRun();
};

class MailiousCodeInjection : public NativeModule {
public:
	MailiousCodeInjection();
	ResultSet* ModuleRun();
};

class ValidSvcHost : public NativeModule {
public:
	ValidSvcHost();
	ResultSet* ModuleRun();
};
#endif