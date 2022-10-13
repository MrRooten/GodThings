#pragma once
#include "public.h"
#include <string>
class SystemUtils {
public:
	static DWORD GetSystemVersion();
	static WORD arch;
	static WORD GetSystemArchitecture();
};