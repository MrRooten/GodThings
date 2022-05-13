#include "EvtInfo.h"
#include "StringUtils.h"
#include <wctype.h>
Evt::Evt(EVT_HANDLE hEvent) {
    this->_hEvent = hEvent;
}

Evt::Evt(std::wstring xml) {
    this->_xml = xml;
}
DWORD Evt::SetXml() {
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    // The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
    if (!EvtRender(NULL, _hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, _hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    wprintf(L"\n\n%s", pRenderedContent);
    this->xml = pRenderedContent;

cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}
std::wstring Evt::GetXml() {
    if (this->xml.size() == 0) {
        SetXml();
    }
    return xml;
}


DWORD GetQueryStatusProperty(EVT_QUERY_PROPERTY_ID Id, EVT_HANDLE hResults, PEVT_VARIANT& pProperty) {
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;

    if (!EvtGetQueryInfo(hResults, Id, dwBufferSize, pProperty, &dwBufferUsed))
    {
        status = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == status)
        {
            dwBufferSize = dwBufferUsed;
            pProperty = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pProperty)
            {
                EvtGetQueryInfo(hResults, Id, dwBufferSize, pProperty, &dwBufferUsed);
            }
            else
            {
                wprintf(L"realloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtGetQueryInfo failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

cleanup:

    return status;
}



std::wstring EvtFilter::GetXMLQuery() {
    std::wstring resXML;
    std::vector<std::wstring> _levels;
    std::wstring levelsString;
    if (this->level != 0) {
        if (this->level & 0x00000001 != 0) {
            _levels.push_back(L"Level=0");
        }
        if (this->level & 0x00000010 != 0) {
            _levels.push_back(L"Level=1");
        }
        if (this->level & 0x00000100 != 0) {
            _levels.push_back(L"Level=2");
        }
        if (this->level & 0x00001000 != 0) {
            _levels.push_back(L"Level=3");
        }
        if (this->level & 0x00010000 != 0) {
            _levels.push_back(L"Level=4");
        }
        levelsString = StringUtils::StringsJoin(_levels, L" or ");
        levelsString = L"(" + levelsString + L")";
    }


    std::vector<std::wstring> _providers;
    std::wstring providersString;
    for (std::wstring provider : this->providers) {
        WCHAR providerItemFormat[] = L"@Name='%s'";
        WCHAR providerItem[200];
        swprintf_s(providerItem, providerItemFormat, provider.c_str());
        _providers.push_back(providerItem);
    }
    if (_providers.size() != 0) {
        providersString = StringUtils::StringsJoin(_providers, L" or ");
    }
    providersString = L"Provider[" + providersString + L"]";

    ULONG64 uint64Keywords = 0;
    std::wstring _keyword;
    std::wstring keywordString;
    for (std::wstring keyword : this->keywords) {
        if (this->_keywordsMap.count(keyword) == 0) {
            continue;
        }
        uint64Keywords = uint64Keywords | this->_keywordsMap[keyword];
    }
    if (this->keywords.size() != 0) {
        _keyword = std::to_wstring(uint64Keywords);
        keywordString = L"band(Keywords," + _keyword + L")";
    }

    std::wstring _time;
    std::wstring timeString;
    do {
        if (this->timeFilterType == ANY_TIME) {
            break;
        }
        else if (this->timeFilterType == TIME_RANGE) {
            _time += L"@SystemTime&gt;='" + this->begin.ToISO8601() + L"'";
            _time += L" and @SystemTime&lt;='" + this->end.ToISO8601() + L"'";
        }
        else if (this->timeFilterType == TIME_TO_NOW) {
            _time += L"timediff(@SystemTime)&lt;=" + std::to_wstring(this->toNow.ToNowULONG64());
        }
        timeString = L"TimeCreated[" + _time + L"]";
    } while (0);

    std::vector<std::wstring> _ids;
    std::vector<std::wstring> _idsTmp;
    std::vector<std::wstring> _idsStrings;
    std::wstring idsString;
    if (this->ids.size() != 0) {
        _ids = StringUtils::StringSplit(this->ids, L",");
        for (auto _id : _ids) {
            std::wstring id = StringUtils::Trim(_id);
            if (StringUtils::IsNumeric(id) != TRUE && id.find(L"-") == -1) {
                continue;
            }

            if (id.find(L"-") != -1) {
                std::vector<std::wstring> _tmpForRange;
                _tmpForRange = StringUtils::StringSplit(id, L"-");
                if (_tmpForRange.size() != 2) {
                    continue;
                }

                if (StringUtils::IsNumeric(_tmpForRange[0]) == FALSE ||
                    StringUtils::IsNumeric(_tmpForRange[1]) == FALSE) {
                    continue;
                }
                
            }
            _idsTmp.push_back(id);
        }

        for (auto id : _idsTmp) {
            std::wstring _tmpString;
            if (StringUtils::IsNumeric(id)) {
                _tmpString = L"EventID=" + id;
                _idsStrings.push_back(_tmpString);
            }
            else {
                auto _tmpVs = StringUtils::StringSplit(id, L"-");
                auto _start = _tmpVs[0];
                auto _end = _tmpVs[1];
                if (std::stoi(_start) > std::stoi(_end)) {
                    continue;
                }
                _tmpString = L"(EventID &gt;= " + _start + L" and EventID &lt;= " + _end + L")";
                _idsStrings.push_back(_tmpString);
            }
        }
        idsString = StringUtils::StringsJoin(_idsStrings, L" or ");
        idsString = L"(" + idsString + L")";
    }

    std::vector<std::wstring> resVs;
    if (providers.size() != 0) {
        resVs.push_back(providersString);
    }

    if (levelsString.size() != 0) {
        resVs.push_back(levelsString);
    }
    
    if (timeString.size() != 0) {
        resVs.push_back(timeString);
    }

    if (keywordString.size() != 0) {
        resVs.push_back(keywordString);
    }

    if (idsString.size() != 0) {
        resVs.push_back(idsString);
    }

    resXML = StringUtils::StringsJoin(resVs, L" and ");
    return L"<QueryList>\n" \
        L"    <Query Path='" + this->logName + L"'>\n" \
        L"        <Select Path='Application'> *[System[" + resXML + L"]]</Select>\n" \
        L"    </Query>\n" \
        L"</QueryList>\n";
    /*return L"<QueryList>" \
        L"      <Query Path=\"Application\">"\
        L"          <Select Path=\"Application\"> *[System[(Level=1 or Level=2 or Level=3 or Level=4 or Level=0 or Level=5) and TimeCreated[timediff(@SystemTime) &lt;=43200000]]]</Select>"\
        L"      </Query>"
        L"</QueryList>";*/
}

#define ARRAY_SIZE 10
DWORD EvtInfo::EnumEventLogs(EvtFilter filter, EvtCallback callback) {
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    PEVT_VARIANT pPaths = NULL;
    PEVT_VARIANT pStatuses = NULL;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

    hResults = EvtQuery(NULL, NULL, filter.GetXMLQuery().c_str(), EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
    if (NULL == hResults) {
        // Handle error.
        goto cleanup;
    }
    if (status = GetQueryStatusProperty(EvtQueryNames, hResults, pPaths))
        goto cleanup;

    if (status = GetQueryStatusProperty(EvtQueryStatuses, hResults, pStatuses))
        goto cleanup;

    for (DWORD i = 0; i < pPaths->Count; i++) {
        wprintf(L"%s (%lu)\n", pPaths->StringArr[i], pStatuses->UInt32Arr[i]);
        status += pStatuses->UInt32Arr[i];
    }

    if (status != NULL) {
        goto cleanup;
    }

    

    while (true) {
        // Get a block of events from the result set.
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError())) {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }

        // For each event, call the PrintEvent function which renders the
        // event for display. PrintEvent is shown in RenderingEvents.
        for (DWORD i = 0; i < dwReturned; i++) {
            Evt evt(hEvents[i]);
            if (ERROR_SUCCESS == (status = callback(&evt))) {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else {
                goto cleanup;
            }
        }
    }
cleanup:

    if (hResults)
        EvtClose(hResults);

    if (pPaths)
        free(pPaths);

    if (pStatuses)
        free(pStatuses);
    return 0;
}