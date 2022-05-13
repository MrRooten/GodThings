#pragma once
#include "Module.h"

class TestModule : public NativeModule {
public:
	TestModule();
	ResultSet* ModuleRun();
};