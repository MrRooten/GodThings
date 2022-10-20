#include "RegistryUtils.h"
#include "utils.h"
#include <algorithm>
#include "StringUtils.h"
void RegistryUtils::init(const wchar_t* path) {
	this->_withHKeyPath = path;
	std::wstring string = path;
	DWORD backSlash = string.find_first_of(L'\\');
	std::wstring rootKey;
	if (backSlash == -1) {
		rootKey = string;
	}
	else {
		rootKey = string.substr(0, backSlash);
	}
	HKEY hKey = 0;
	std::transform(
		rootKey.begin(), rootKey.end(),
		rootKey.begin(),
		towupper);
	if (rootKey == L"HKEY_CLASSES_ROOT") {
		hKey = HKEY_CLASSES_ROOT;
	}
	else if (rootKey == L"HKEY_CURRENT_CONFIG") {
		hKey = HKEY_CURRENT_CONFIG;
	}
	else if (rootKey == L"HKEY_CURRENT_USER") {
		hKey = HKEY_CURRENT_USER;
	}
	else if (rootKey == L"HKEY_LOCAL_MACHINE") {
		hKey = HKEY_LOCAL_MACHINE;
	}
	else if (rootKey == L"HKEY_USERS") {
		hKey = HKEY_USERS;
	}

	this->hKey = hKey;
	if (backSlash != -1) {
		this->registryPath = string.substr(string.find_first_of(L'\\') + 1, string.size() - string.find_first_of(L'\\'));
	}
	else {
		this->registryPath = L"";
	}
	this->error = ERROR_SUCCESS;
}

RegistryUtils::RegistryUtils(std::wstring &string) {
	std::wstring save = string.c_str();
	StringUtils::trim(save, L"\\");
	init(save.c_str());
}

RegistryUtils::RegistryUtils(const wchar_t* path) {
	std::wstring save = path;
	StringUtils::trim(save, L"\\");
	init(save.c_str());
}

DWORD RegistryUtils::GetValueType(std::wstring &valueName,PDWORD pType) {
	DWORD status;
	DWORD res;
	status = RegGetValueW(this->hKey, this->registryPath.c_str(), NULL, RRF_RT_ANY, &res, NULL, NULL);
	*pType = res;
	if (GetLastError() != ERROR_SUCCESS) {
		LOG_DEBUG_REASON("Error RegGetValueW");
	}
	return status;
}

DWORD RegistryUtils::GetValueType(const wchar_t* valueName, PDWORD pType) {
	std::wstring _valueName;
	return this->GetValueType(_valueName, pType);
}

std::vector<std::pair<std::wstring, std::wstring>> RegistryUtils::ListKeyValue()
{
	std::vector<std::pair<std::wstring, std::wstring>> retValues;

	DWORD numOfValues;
	DWORD maxValueNameLen;
	DWORD maxValueDataLen;
	LONG retCode;
	HKEY regKey;
	RegOpenKeyW(this->hKey, this->registryPath.c_str(), &regKey);

	retCode = RegQueryInfoKey(regKey, NULL, NULL, NULL, NULL, NULL, NULL, &numOfValues, &maxValueNameLen, &maxValueDataLen, NULL, NULL);
	if ((retCode == ERROR_SUCCESS) && (numOfValues != 0))
	{
		WCHAR* valueName = new WCHAR[maxValueNameLen + 1];

		WCHAR* valueData = new WCHAR[maxValueDataLen + 1];

		for (size_t i = 0; i < numOfValues; i++)
		{
			DWORD valueNameBuferSize = maxValueNameLen + 1;
			DWORD valueDataBufferSize = maxValueDataLen + 1;

			retCode = RegEnumValueW(regKey, i, valueName, &valueNameBuferSize, NULL, NULL, (LPBYTE)valueData, &valueDataBufferSize);
			if (retCode == ERROR_SUCCESS)
			{
				auto pair = std::make_pair(std::wstring(valueName), std::wstring(valueData));
				retValues.push_back(pair);
			}
		}
		delete[] valueName;
		delete[] valueData;
	}
	if (regKey != NULL)
		RegCloseKey(regKey);
	return retValues;
}

std::vector<std::wstring> RegistryUtils::ListValueNames() {
	std::vector<std::wstring> retValues;

	DWORD numOfValues;
	DWORD maxValueNameLen;
	LONG retCode;
	HKEY regKey;
	RegOpenKeyW(this->hKey, this->registryPath.c_str(), &regKey);

	retCode = RegQueryInfoKey(regKey, NULL, NULL, NULL, NULL, NULL, NULL, &numOfValues, &maxValueNameLen, NULL, NULL, NULL);
	if ((retCode == ERROR_SUCCESS) && (numOfValues != 0))
	{
		WCHAR* valueName = new WCHAR[maxValueNameLen + 1];

		for (size_t i = 0; i < numOfValues; i++)
		{
			DWORD valueNameBuferSize = maxValueNameLen + 1;

			retCode = RegEnumValueW(regKey, i, valueName, &valueNameBuferSize, NULL, NULL, NULL, NULL);
			if (retCode == ERROR_SUCCESS)
			{
				retValues.push_back(valueName);
			}
		}
		delete[] valueName;
	}
	if (regKey != NULL)
		RegCloseKey(regKey);
	return retValues;
}

std::vector<std::wstring> RegistryUtils::ListSubKeys() {
	int i = 0;
	DWORD size = 1024;
	WCHAR name[1024];
	std::vector<std::wstring> res;
	HKEY regKey;
	DWORD status = RegOpenKeyW(hKey, this->registryPath.c_str(), &regKey);
	while ((status = RegEnumKeyW(regKey, i, name, size)) != ERROR_NO_MORE_ITEMS) {
		res.push_back(name);
		i++;
		ZeroMemory(name, sizeof(WCHAR) * size);
	}
	RegCloseKey(regKey);
	return res;
}

std::vector<RegistryUtils> RegistryUtils::ListSubKeysChain() {
	std::vector<RegistryUtils> res;
	auto list = this->ListSubKeys();
	for (auto& subkey : list) {
		auto target = this->_withHKeyPath + L"\\" + subkey;
		res.push_back(RegistryUtils(target));
	}
	return res;
}

std::wstring& RegistryUtils::GetPath() {
	return this->registryPath;
}

std::wstring& RegistryUtils::GetKeyName() {
	if (this->keyName.size() == 0) {
		size_t i = this->registryPath.find_last_of(L'\\');
		this->keyName = this->registryPath.substr(i + 1, this->registryPath.size() - i);
	}
	return this->keyName;
}

BytesBuffer RegistryUtils::GetValueStatic(std::wstring &path,std::wstring &key) {
	BytesBuffer res;
	std::wstring rootKey = path.substr(0, path.find_first_of(L'\\'));
	HKEY hKey = 0;
	HKEY regKey;
	std::transform(
		rootKey.begin(), rootKey.end(),
		rootKey.begin(),
		towupper);
	if (rootKey == L"HKEY_CLASSES_ROOT") {
		hKey = HKEY_CLASSES_ROOT;
	}
	else if (rootKey == L"HKEY_CURRENT_CONFIG") {
		hKey = HKEY_CURRENT_CONFIG;
	}
	else if (rootKey == L"HKEY_CURRENT_USER") {
		hKey = HKEY_CURRENT_USER;
	}
	else if (rootKey == L"HKEY_LOCAL_MACHINE") {
		hKey = HKEY_LOCAL_MACHINE;
	}
	else if (rootKey == L"HKEY_USERS") {
		hKey = HKEY_USERS;
	}

	std::wstring registryPath = path.substr(path.find_first_of(L'\\') + 1, path.size() - path.find_first_of(L'\\'));
	
	//registryPath = path.substr(path.find_first_of(L'\\')+1, path.find_last_of(L'\\')-path.find_first_of(L'\\'));
	//std::wstring valueName = path.substr(path.find_last_of(L'\\')+1, path.size() - path.find_last_of(L'\\'));
	DWORD size = 0x100;
	DWORD status = 0;
	PBYTE bytes = (PBYTE)GlobalAlloc(GPTR, 0x100);
	//status = RegGetValueW(hKey, registryPath.c_str(), valueName.c_str(), RRF_RT_ANY, &type, bytes, &size);
	status = RegOpenKeyW(hKey, registryPath.c_str(), &regKey);
	if (status != ERROR_SUCCESS) {
		return res;
	}
	status = RegQueryValueExW(
		regKey,
		key.c_str(),
		0,
		NULL,
		bytes,
		&size
	);
	if (status == ERROR_INSUFFICIENT_BUFFER) {
		bytes = (PBYTE)GlobalAlloc(GPTR, size);
		//status = RegGetValueW(hKey, registryPath.c_str(), valueName.c_str(), RRF_RT_ANY, &type, bytes, &size);
		res = std::string((CHAR*)bytes,size);
		GlobalFree(bytes);
	}
	else if (status == ERROR_SUCCESS) {
		res = std::string((CHAR*)bytes,size);
		GlobalFree(bytes);
	}
	else {
		GlobalFree(bytes);
		res = "";
	}
	if (regKey != NULL)
		RegCloseKey(regKey);
	return res;
}

BytesBuffer RegistryUtils::GetValueStatic(const wchar_t* path, const wchar_t* key) {
	std::wstring _path = path;
	std::wstring _key = key;
	return RegistryUtils::GetValueStatic(_path, _key);
}

FILETIME RegistryUtils::GetLastWriteTime() {
	FILETIME ft = {0};
	HKEY key = NULL;
	RegOpenKeyW(this->hKey, this->registryPath.c_str(), &key); 
	DWORD status = RegQueryInfoKeyW(
		key,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&ft
	);
	RegCloseKey(key);
	return ft;
}
