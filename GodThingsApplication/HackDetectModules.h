#pragma once
#include "Module.h"
class ZeroLogon : public NativeModule {
public:
	ZeroLogon();
	ResultSet* ModuleRun();
};

class PrintNightmare : public NativeModule {
public:
	PrintNightmare();
	ResultSet* ModuleRun();
};
