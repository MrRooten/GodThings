#pragma once
#ifndef __H_WMI_utils
#define __H_WMI_utils


#include "public.h"
#include "utils.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <map>
#include <variant>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
class WmiTaker {
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;
public:
	using WmiVariable = std::variant<std::wstring, int, short, double, UINT64>;
	using WmiResult = std::vector<std::map<std::wstring, WmiVariable>>;
	WmiTaker();
	WmiResult take(const wchar_t* sql);
	~WmiTaker();
};
#endif // !1