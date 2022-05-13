#pragma once
#include "public.h"
#include <winevt.h>

#include <vector>
#include <string>
#include <map>
#include <vector>
class Provider {
private:
public:
	std::wstring logName;
	std::wstring sourceName;
	std::wstring guid;
	HKEY hKey;
	std::wstring resourceDll;
	HMODULE hResources = NULL;

	Provider();
	DWORD Initialize(std::wstring logName,std::wstring sourceName);
	HANDLE GetResourceHandle();
	~Provider();
};

class ProviderManager {
private:
	std::map<std::wstring, Provider*> _map;
public:
	Provider* GetProvider(std::wstring logName, std::wstring source);
	~ProviderManager();
};
class EventLog {
private:
	EVENTLOGRECORD* _record;
	DWORD SetRecordSize();

	DWORD SetRecordNumber();

	DWORD SetTimeGenerate();

	DWORD SetTimeWritten();

	DWORD SetEventId();

	DWORD SetEventType();

	DWORD SetMsg();

	DWORD SetLogName();

	DWORD SetSourceName();

	DWORD SetData();
public:
	std::wstring logName;
	std::wstring sourceName;
	Provider* provider = NULL;
	DWORD eventId = -1;
	DWORD recordId = -1;
	DWORD version = -1;
	DWORD recordSize = -1;
	std::wstring message;
	DWORD timeGenerate = -1;
	DWORD timeWritten = -1;
	WORD eventType = -1;
	std::wstring data;
	EventLog();

	~EventLog();
	DWORD Initialize(EVENTLOGRECORD* record);
	
	DWORD InitProvider(Provider* provider);
	std::wstring GetLogName();

	std::wstring GetSourceName();

	DWORD GetRecordSize();

	DWORD GetRecordNumber();

	DWORD GetTimeGenerate();

	DWORD GetTimeWritten();

	DWORD GetEventId();

	WORD  GetEventType();

	std::wstring GetData();

	std::wstring GetMsg();
};

class EventLogFilter {
private:
	std::vector<DWORD> ids;
public:
	std::wstring logName;
	SYSTEMTIME begin;
	SYSTEMTIME end;
	std::wstring source;
	std::wstring idsPattern;
	enum LogLevel {
		LOG_KEY = 0x00000000,
		LOG_WARNING = 0x00000001,
		LOG_DETAIL = 0x00000010,
		LOG_ERROR = 0x00000100,
		LOG_INFO = 0x00001000,
	};
	LogLevel level;
	std::wstring user;
	std::wstring computer;
	BOOL IsValid(EVENTLOGRECORD *eventLog);
	VOID Initialize();
};

typedef VOID (*EventLogCallback)(EventLog* eventLog);

class EventLogUtils {
public:
	DWORD EnumEventLogs(EventLogFilter filter, EventLogCallback callback);
};