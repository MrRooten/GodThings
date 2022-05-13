#include "EventLogUtils.h"
#include <map>
#include <sstream>
#include <iostream>
DWORD Provider::Initialize(std::wstring logName, std::wstring sourceName) {
    this->logName = logName;

    this->sourceName = sourceName;
    wchar_t regKey[100];
    wchar_t dllName[200];
    wchar_t valueBuf[200];
    DWORD dwType;
    DWORD dwSize;

    wsprintfW(regKey, L"SYSTEM\\CURRENTCONTROLSET\\SERVICES\\EVENTLOG\\%s\\%s", logName.c_str(), sourceName.c_str());
    if (RegOpenKeyW(HKEY_LOCAL_MACHINE, regKey, &this->hKey) == ERROR_SUCCESS) {
        dwType = REG_EXPAND_SZ;
        dwSize = sizeof(valueBuf);
        if (RegQueryValueExW(hKey, L"EventMessageFile", 0, &dwType, (unsigned char*)&valueBuf, &dwSize) != ERROR_SUCCESS) {
            //printf("Some error occurred!\n");
        }
        ExpandEnvironmentStringsW(valueBuf, dllName, dwSize);
    }

    hResources = LoadLibraryExW(dllName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    return 0;
}
Provider::Provider() {

}

Provider::~Provider() {
    FreeLibrary(hResources);
}

Provider* ProviderManager::GetProvider(std::wstring logName, std::wstring sourceName) {
    if (_map.count(sourceName) > 0) {
        return _map[sourceName];
    }

    Provider* provider = new Provider();
    if (provider == NULL) {
        return NULL;
    }
    DWORD status = provider->Initialize(logName, sourceName);
    if (status != ERROR_SUCCESS) {
        delete provider;
        return NULL;
    }
    _map[logName] = provider;
    return provider;
}

ProviderManager::~ProviderManager() {
    for (auto item : _map) {
        if (item.second != NULL) {
            delete item.second;
        }
    }
}
EventLog::EventLog() {

}

EventLog::~EventLog() {
    if (this->_record != NULL) {
        LocalFree(this->_record);
    }
}

HANDLE Provider::GetResourceHandle() {
    return this->hResources;
}


DWORD EventLog::Initialize(EVENTLOGRECORD* record) {
    this->_record = (EVENTLOGRECORD*)LocalAlloc(GPTR, record->Length);
    if (this->_record == NULL) {
        return GetLastError();
    }

    memcpy_s(this->_record, record->Length, record, record->Length);
    this->eventId = record->EventID;
    this->recordId = record->RecordNumber;
}


DWORD EventLog::InitProvider(Provider* provider) {
    this->provider = provider;
    return 0;
}

DWORD EventLog::SetLogName() {
    return 0;
}

std::wstring EventLog::GetLogName() {
    if (this->logName.size() == 0) {
        SetLogName();
    }
    return this->logName;
}

DWORD EventLog::SetSourceName() {
    this->sourceName = (LPWSTR)((LPBYTE)_record + sizeof(EVENTLOGRECORD));
    return 0;
}

std::wstring EventLog::GetSourceName() {
    if (this->sourceName.size() == 0) {
        SetSourceName();
    }
    return this->sourceName;
}

DWORD EventLog::GetEventId() {
    if (this->eventId == -1) {
        SetEventId();
    }
    return this->eventId;
}

DWORD EventLog::SetEventId() {
    this->eventId = this->_record->EventID;
    return 0;
}

DWORD EventLog::GetRecordNumber() {
    if (this->recordId == -1) {
        SetRecordNumber();
    }
    return this->recordId;
}

DWORD EventLog::SetRecordNumber() {
    this->recordId = this->_record->RecordNumber;
    return 0;
}

DWORD EventLog::GetRecordSize() {
    if (this->recordSize == -1) {
        SetRecordSize();
    }
    return this->recordSize;
}

DWORD EventLog::SetRecordSize() {
    this->recordSize = this->_record->Length;
    return 0;
}

DWORD EventLog::GetTimeGenerate() {
    if (this->timeGenerate == -1) {
        SetTimeGenerate();
    }
    return this->timeGenerate;
}

DWORD EventLog::SetTimeGenerate() {
    this->timeGenerate = this->_record->TimeGenerated;
    return 0;
}

DWORD EventLog::GetTimeWritten() {
    if (this->timeWritten == -1) {
        SetTimeWritten();
    }
    return this->timeWritten;
}

DWORD EventLog::SetTimeWritten() {
    this->timeWritten = this ->_record->TimeWritten;
    return 0;
}

WORD EventLog::GetEventType() {
    if (this->eventType == -1) {
        SetEventType();
    }
    return this->eventType;
}

DWORD EventLog::SetEventType() {
    this->eventType = this->_record->EventType;
    return 0;
}

std::wstring EventLog::GetData() {
    if (this->data.size() == 0) {
        SetData();
    }
    return this->data;
}

DWORD EventLog::SetData() {
    if (this->_record->DataLength == 0) {
        return 0;
    }
    this->data = (LPWSTR)((PBYTE)this->_record + this->_record->DataOffset);
    return 0;
}
VOID EventLogFilter::Initialize() {
    if (this->idsPattern.size() != 0) {
        std::vector<std::wstring> tmp_strings;
        std::wistringstream f(this->idsPattern);
        std::wstring s;
        while (std::getline(f, s, L',')) {
            tmp_strings.push_back(s);
        }

    }
}

BOOL EventLogFilter::IsValid(EVENTLOGRECORD* record) {
    return TRUE;
}

std::wstring EventLog::GetMsg() {
    if (this->message.size() == 0) {
        SetMsg();
    }
    return this->message;
}
DWORD EventLog::SetMsg() {
    HANDLE hResources = this->provider->GetResourceHandle();
    if (hResources == NULL) {
        return GetLastError();
    }

    LPWSTR message;
    DWORD fm_flags = 0;
    fm_flags |= FORMAT_MESSAGE_FROM_HMODULE;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_FROM_SYSTEM;
    FormatMessageW(
        fm_flags,
        hResources,
        this->eventId,
        0,
        (LPWSTR)&message,
        0,
        NULL
    );
    if (message == NULL) {
        return GetLastError();
    }
    this->message = message;
}

DWORD EventLogUtils::EnumEventLogs(EventLogFilter filter,EventLogCallback EventLogProc) {
    DWORD dwNeeded = 0;
    DWORD dwRead = 0;
    DWORD dwSize = 0x3000;
    EVENTLOGRECORD* pevlr = NULL;
    PVOID buffer = NULL;
    HANDLE hEventLog = OpenEventLogW(NULL, filter.logName.c_str());
    ProviderManager providerManager;
    std::map<std::wstring, Provider*> providerMap;
    if (hEventLog == NULL) {
        goto cleanup;
    }

    if (filter.logName.size() == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    pevlr = (EVENTLOGRECORD*)LocalAlloc(GPTR, dwSize);
    if (pevlr == NULL) {
        goto cleanup;
    }
    do {
        ReadEventLogW(
            hEventLog,                // Event log handle   
            EVENTLOG_FORWARDS_READ |          // Reads forward   
            EVENTLOG_SEQUENTIAL_READ,         // Sequential read   
            0,                                // Ignored for sequential read   
            pevlr,                            // Pointer to buffer   
            dwSize,                      // Size of buffer   
            &dwRead,                          // Number of bytes read   
            &dwNeeded);
        DWORD dwRead2 = dwRead;
        EVENTLOGRECORD* pevlr2 = pevlr;
        while (dwRead2 > 0) {
            DWORD dwRecordSize = pevlr2->Length;
            
            if (filter.IsValid(pevlr2)) {
                EventLog eventLog;
                eventLog.Initialize(pevlr2);
                eventLog.InitProvider(providerManager.GetProvider(filter.logName, eventLog.GetSourceName()));
                EventLogProc(&eventLog);
            }
            dwRead2 -= pevlr2->Length;
            pevlr2 = (EVENTLOGRECORD*)((LPBYTE)pevlr2 + pevlr2->Length);
        }
    } while (dwRead > 0);

cleanup:
    
    if (buffer != NULL) {
        LocalFree(buffer);
    }

    if (hEventLog != NULL) {
        CloseEventLog(hEventLog);
    }
    
    return GetLastError();
}