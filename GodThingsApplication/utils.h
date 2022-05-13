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
	static INT64 BytesToINT64(PBYTE bytes);
	static INT32 BytesToINT32(PBYTE bytes);
	static INT16 BytesToINT16(PBYTE bytes);
	static MPEBytes INT16ToBytes(INT16 integer);
	static MPEBytes INT32ToBytes(INT32 integer);
	static MPEBytes INT64ToBytes(INT64 integer);
	MPEBytes();
	MPEBytes(PBYTE bytes,size_t size);
	PBYTE ToBytes();
	VOID AddBytes(PBYTE bytes,size_t size);
	VOID AddBytes(MPEBytes &mpeBytes);
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
#endif