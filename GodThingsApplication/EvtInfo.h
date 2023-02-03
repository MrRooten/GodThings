#pragma once
#ifndef _EVT_INFO_H
#define _EVT_INFO_H

#include "public.h"
#include <winevt.h>
#include <string>
#include <vector>
#include <map>
#include "utils.h"
#pragma comment(lib, "wevtapi.lib")
class Evt {
private:
	EVT_HANDLE _hEvent;
	DWORD SetXml();
	std::wstring _xml;
public:
	Evt(EVT_HANDLE hEvent);
	Evt(std::wstring xml);
	std::wstring& GetXml();
	Evt();
};

class EvtFilter {
private:
	std::map<std::wstring, ULONG64> _keywordsMap = {
		{L"SQM",2251799813685248},
		{L"WdiDiagnostic",1125899906842624},
		{L"WdiContext",562949953421312},
		{L"ResponseTime",281474976710656},
		{L"None",0},
		{L"EventLogClassic",36028797018963968},
		{L"CorrelationHint2",18014398509481984},
		{L"CorrelationHint",4503599627370496},
		{L"AuditSuccess",9007199254740992},
		{L"AuditFailure",4503599627370496}
	};
public:
	std::wstring logName;
	std::wstring ids;
	std::wstring source;
	std::vector<std::wstring> providers;
	std::vector<std::wstring> keywords;
	enum TimeFilterType {
		ANY_TIME = 0,
		TIME_RANGE = 1,
		TIME_TO_NOW = 2
	};
	TimeFilterType timeFilterType = ANY_TIME;
	GTTime begin;
	GTTime end;
	GTTime toNow;
	enum LogLevel {
		LOG_NONE = 0x00000000,
		LOG_KEY = 0x00000001,
		LOG_WARNING = 0x00000010,
		LOG_DETAIL = 0x00000100,
		LOG_ERROR = 0x00001000,
		LOG_INFO = 0x00010000,
	};
	DWORD level = 0;
	std::wstring user;
	std::wstring computer;
	std::wstring GetXMLQuery();
	EvtFilter();
};

typedef DWORD(*EvtCallback)(Evt* evt,PVOID data);

class EvtSet {
	std::vector<Evt> evts;
public:
	DWORD GetSize();
	std::vector<Evt>& GetAllEvts();
	DWORD AddEvt(Evt evt);
	EvtSet();
};
class EvtInfo {
public:
	DWORD EnumEventLogs(EvtFilter filter, EvtCallback callback, PVOID data, bool reverse = false);
	static EvtSet* GetEvtSetByEventId(const wchar_t* ids,const wchar_t* logName);
};

#endif // !_EVT_INFO_H