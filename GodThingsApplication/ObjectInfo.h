#pragma once
#ifndef _OBJECT_INFO_H
#define _OBJECT_INFO_H


#include "NtObjectInfo.h"
#include "public.h"
#include <string>
class ObjectInfo {
public:
	static std::wstring GetTypeName(HANDLE hObject);

	static std::wstring GetObjectName(HANDLE hObject);

	static bool IsValidObject(HANDLE hObject);

	static OBJECT_BASIC_INFORMATION* GetObjectInfo(HANDLE hObject);
};
#endif // !_OBJECT_INFO_H