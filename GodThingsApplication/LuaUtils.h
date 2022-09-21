#pragma once
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

class LuaVM {
	lua_State* l_State;

public:
	LuaVM();
	~LuaVM();
	void init();
	void run_string(const char* s);
	void run_file(const char* f);
	void run_func(const char* func);
};