#pragma once
#include "NtObjectInfo.h"
#include "public.h"
#include <string>
class ObjectInfo {
public:
	static std::wstring GetTypeName(HANDLE hObject);

	static std::wstring GetObjectName(HANDLE hObject);

};