#pragma once
#ifndef _UTILS_H
#define _UTILS_H
#include "public.h"
#include <string>
#include <algorithm>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>


typedef std::wstring GTWString;
typedef std::string GTString;

class MPEBytes {
private:
	
public:
	PBYTE bytes;
	size_t size;
	DWORD error;
	static UINT64 BytesToINT64B(PBYTE bytes);
	static UINT64 BytesToINT64L(PBYTE bytes);
	static UINT32 BytesToINT32B(PBYTE bytes);
	static UINT32 BytesToINT32L(PBYTE bytes);
	static UINT16 BytesToINT16B(PBYTE bytes);
	static UINT16 BytesToINT16L(PBYTE bytes);
	static MPEBytes INT16ToBytesB(INT16 integer);
	static MPEBytes INT32ToBytesB(INT32 integer);
	static MPEBytes INT64ToBytesB(INT64 integer);
	MPEBytes();
	MPEBytes(PBYTE bytes,size_t size);
	PBYTE ToBytes();
	VOID AddBytes(PBYTE bytes,size_t size);
	VOID AddBytes(MPEBytes &mpeBytes);
	PBYTE& GetBytes();
	~MPEBytes();
};

#define get_i64b(bs) (INT64)MPEBytes::BytesToINT64B((PBYTE)bs)
#define get_i32b(bs) (INT32)MPEBytes::BytesToINT32B((PBYTE)bs)
#define get_i64l(bs) (INT64)MPEBytes::BytesToINT64L((PBYTE)bs)
#define get_i32l(bs) (INT32)MPEBytes::BytesToINT32L((PBYTE)bs)
#define get_i16b(bs) (INT16)MPEBytes::BytesToINT16B((PBYTE)bs)
#define get_i16l(bs) (INT16)MPEBytes::BytesToINT16L((PBYTE)bs)
#define get_u64b(bs) MPEBytes::BytesToINT64B((PBYTE)bs)
#define get_u32b(bs) MPEBytes::BytesToINT32B((PBYTE)bs)
#define get_u64l(bs) MPEBytes::BytesToINT64L((PBYTE)bs)
#define get_u32l(bs) MPEBytes::BytesToINT32L((PBYTE)bs)
#define get_u16b(bs) MPEBytes::BytesToINT16B((PBYTE)bs)
#define get_u16l(bs) MPEBytes::BytesToINT16L((PBYTE)bs)

class GTTime {
	FILETIME fTime;
	SYSTEMTIME sysTime;
public:
	DWORD year = 0;
	DWORD month = 0;
	DWORD day = 0;
	DWORD hour = 0;
	DWORD minute = 0;
	DWORD second = 0;
	DWORD millisecond = 0;
	GTTime(FILETIME &filetime);
	GTTime(SYSTEMTIME &systime);
	GTTime(const char* time);
	GTTime(const wchar_t* time);
	GTTime();
	std::wstring ToISO8601();
	std::wstring String_utc_to_local();
	std::wstring String();
	static GTTime GetTime();
	static GTTime FromTimeStamp(UINT32 timestamp);
	static GTTime FromTimeStamp64(UINT64 timestamp);
	static GTTime FromISO8601(GTWString time);
	ULONG64 ToNowULONG64();
	bool operator<(GTTime& other);
	bool operator>(GTTime& other);
	bool operator==(GTTime& other);
	bool operator>=(GTTime& other);
	bool operator<=(GTTime& other);
	INT64 operator-(GTTime& other);
};

enum LOG_LEVEL {
	DEBUG_LEVEL = 3,
	INFO_LEVEL=2,
	WARNING_LEVEL=1,
	ERROR_LEVEL=0
};

VOID GTPrintln(const WCHAR* messageFormat, ...);

extern LOG_LEVEL GlobalLogLevel;
VOID SetGloablLogLevel(LOG_LEVEL level);

VOID Logln(LOG_LEVEL logLevel, const WCHAR* messageFormat, ...);
#define LOG_DEBUG_REASON(msg) Logln(DEBUG_LEVEL, L"[%s:%s:%d]:%s:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__,msg, GetLastError(), GetLastErrorAsString())
#define LOG_ERROR_REASON(msg) Logln(ERROR_LEVEL, L"[%s:%s:%d]:%s:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__,msg, GetLastError(), GetLastErrorAsString())
#define LOG_WARN_REASON(msg) Logln(WARNING_LEVEL, L"[%s:%s:%d]:%s:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__,msg, GetLastError(), GetLastErrorAsString())
#define LOG_INFO_REASON(msg) Logln(INFO_LEVEL, L"[%s:%s:%d]:%s:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__,msg, GetLastError(), GetLastErrorAsString())
#define LOG_DEBUG(msg) Logln(DEBUG_LEVEL, L"[%s:%s:%d]:%s", __FILEW__, __FUNCTIONW__, __LINE__,msg)
#define LOG_ERROR(msg) Logln(ERROR_LEVEL, L"[%s:%s:%d]:%s", __FILEW__, __FUNCTIONW__, __LINE__,msg)
#define LOG_WARN(msg) Logln(WARNING_LEVEL, L"[%s:%s:%d]:%s", __FILEW__, __FUNCTIONW__, __LINE__,msg)
#define LOG_INFO(msg) Logln(INFO_LEVEL, L"[%s:%s:%d]:%s", __FILEW__, __FUNCTIONW__, __LINE__,msg)
LPWSTR GetLastErrorAsString();

std::wstring GetLastErrorAsStringThreadSafe();

std::wstring s2ws(const std::string& str);

#define BytesBuffer std::string
#define NewBytesBuffer(bs,len) BytesBuffer(reinterpret_cast<char const*>(bs),len)
using BytesPair = std::pair<PBYTE, size_t>;
using GTRawString = BYTE*;
typedef WCHAR* GTRawWString;


GTWString red_s(const wchar_t* s);
GTWString blue_s(const wchar_t* s);
GTWString green_s(const wchar_t* s);
GTWString yellow_s(const wchar_t* s);

class GTException : public std::exception {
	GTString msg;
public:
	GTException(const char* msg);
	char* what();
};
#endif