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
using namespace std;

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


class GTTime {
public:
	DWORD year = 0;
	DWORD mouth = 0;
	DWORD day = 0;
	DWORD hour = 0;
	DWORD minute = 0;
	DWORD second = 0;
	DWORD millisecond = 0;
	GTTime(FILETIME &filetime);
	GTTime(SYSTEMTIME &systime);
	std::wstring ToISO8601();
	std::wstring ToString();
	static GTTime GetTime();
	ULONG64 ToNowULONG64();
};

enum LOG_LEVEL {
	DEBUG_LEVEL = 3,
	INFO_LEVEL=2,
	WARNING_LEVEL=1,
	ERROR_LEVEL=0
};

VOID GTPrintln(const WCHAR* messageFormat, ...);

static LOG_LEVEL GlobalLogLevel = INFO_LEVEL;

VOID Logln(LOG_LEVEL logLevel, const WCHAR* messageFormat, ...);

LPWSTR GetLastErrorAsString();

std::wstring GetLastErrorAsStringThreadSafe();

std::wstring s2ws(const std::string& str);

#define BytesBuffer std::string
#define NewBytesBuffer(bs,len) BytesBuffer(reinterpret_cast<char const*>(bs),len)
using BytesPair = std::pair<PBYTE, size_t>;
#endif