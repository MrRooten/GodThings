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

