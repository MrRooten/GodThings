#pragma once
#include "public.h"
#include <string>
#include <vector>
#include <ctime>
#include "utils.h"
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef DWORD (*EnumKeyValueCallback)(
	std::wstring key,
	PVOID pValue
	);

class RegistryUtils {
private:
	std::wstring registryPath;
	std::wstring _withHKeyPath;
	std::wstring keyName;
	HKEY hKey;
	void init(const wchar_t* path);
public:
	DWORD error;
	RegistryUtils(std::wstring &path);
	RegistryUtils(const wchar_t* path);
	DWORD GetValueType(std::wstring &valueName,PDWORD pType);
	DWORD GetValueType(const wchar_t* valueName, PDWORD pType);
	std::vector<std::pair<std::wstring, std::wstring>> ListKeyValue();
	std::vector<std::wstring> ListValueNames();
	static BytesBuffer GetValueStatic(std::wstring &path,std::wstring &key);
	static BytesBuffer GetValueStatic(const wchar_t* path, const wchar_t* key);
	FILETIME GetLastWriteTime();
	std::vector<std::wstring> ListSubKeys();
	std::vector<RegistryUtils> ListSubKeysChain();
	RegistryUtils GetSubkeyByName(const wchar_t* name);
	std::wstring& GetPath();
	std::wstring& GetKeyName();
};

class UserAssistParser {
	GTTime lastRun;
	INT32 runCount;
	GTTime focusTime;
	INT32 focusCount;
public:
	UserAssistParser(BytesBuffer buffer);
	UserAssistParser();
	INT32 GetRunCount();
	std::wstring GetLastRun();
	GTTime& GetFocusTime();
	INT32 GetFocusCount();
};

class MUICacheParser {

};

class RunMRUParser {

};

class AppCompatFlagsParser {

};

class BackgroundActivityModeratorParser {

};

class RecentAppsParser {

};