#pragma once
#include <string>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <vector>

class StringUtils {
public:
	template<typename ... Args>
	static std::wstring StringFormat(const std::wstring& format, Args ... args);

	static bool HasEnding(std::wstring const& fullString, std::wstring const& ending);

	static std::wstring ToLower(std::wstring const& str);

	static std::wstring ToUpper(std::wstring const& str);

	static std::wstring StringsJoin(std::vector<std::wstring> vs, std::wstring delim);

	static std::vector<std::wstring> StringSplit(std::wstring s, std::wstring delim);

	static bool IsNumeric(std::wstring s);

	static std::wstring Trim(std::wstring s);

	static std::string ws2s(const std::wstring& wstr);

	static std::string ws2s(const wchar_t* wstr);

	static std::wstring s2ws(const std::string& str);

	static std::wstring s2ws(const char* str);
};