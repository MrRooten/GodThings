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

	static std::wstring StringsJoin(std::vector<std::wstring> &vs, std::wstring &delim);

	static std::wstring StringsJoin(std::vector<std::wstring>& vs, const wchar_t* delim);

	static std::string StringsJoin(std::vector<std::string>& vs, const char* delim);

	static void replaceAll(std::string& str, const std::string& from, const std::string& to);

	static void replaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to);

	static std::vector<std::wstring> StringSplit(std::wstring s, std::wstring delim);

	static bool IsNumeric(std::wstring s);

	static std::wstring Trim(std::wstring s);

	static std::string Trim(std::string s);

	static std::wstring Trim(std::wstring s, std::wstring _t);

	static std::string Trim(std::string s, std::string _t);

	static std::string ws2s(const std::wstring& wstr);

	static std::string ws2s(const wchar_t* wstr);

	static std::wstring s2ws(const std::string& str);

	static std::wstring s2ws(const char* str);

	static std::string& ltrim(std::string& s, const char* t);

	static std::string& rtrim(std::string& s, const char* t);

	static std::string& trim(std::string& s, const char* t);

	static std::wstring& ltrim(std::wstring& s, const wchar_t* t);

	static std::wstring& rtrim(std::wstring& s, const wchar_t* t);

	static std::wstring& trim(std::wstring& s, const wchar_t* t);
};