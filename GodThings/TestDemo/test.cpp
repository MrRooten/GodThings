//#include <windows.h>
//#include <stdio.h>
//#include <tchar.h>
//#include <Psapi.h>
//#ifdef UNICODE
//#define DBGHELP_TRANSLATE_TCHAR
//#endif
//#include <dbghelp.h>
//#include <string>
//#include <iostream>
//#define _UNICODE 1
//#define UNICODE 1
//
//#include <stdlib.h>
//#include <windows.h>
//#include <Softpub.h>
//#include <wincrypt.h>
//#include <wintrust.h>
//
//// Link with the Wintrust.lib file.
//#pragma comment (lib, "wintrust")
//typedef int (*type_RtlAdjustPrivilege)(int, bool, bool, int*);
//HANDLE hProcess;
//DWORD64 BaseOfDll;
//std::string GetLastErrorAsString()
//{
//    //Get the error message ID, if any.
//    DWORD errorMessageID = ::GetLastError();
//    if (errorMessageID == 0) {
//        return std::string(); //No error message has been recorded
//    }
//
//    LPSTR messageBuffer = nullptr;
//
//    //Ask Win32 to give us the string version of that message ID.
//    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
//    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
//        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
//
//    //Copy the error message into a std::string.
//    std::string message(messageBuffer, size);
//
//    //Free the Win32's string's buffer.
//    LocalFree(messageBuffer);
//
//    return message;
//}
//
//BOOL CALLBACK EnumModules(
//    PCTSTR  ModuleName,
//    DWORD BaseOfDll,
//    PVOID   UserContext)
//{
//    UNREFERENCED_PARAMETER(UserContext);
//
//    _tprintf(TEXT_STRING("%08X %s\n"), BaseOfDll, ModuleName);
//    return TRUE;
//}
//
//BOOL CALLBACK EnumSymProc(
//    PSYMBOL_INFO pSymInfo,
//    ULONG SymbolSize,
//    PVOID UserContext)
//{
//    UNREFERENCED_PARAMETER(UserContext);
//
//    
//    SymGetTypeFromName(hProcess, BaseOfDll, pSymInfo->Name, pSymInfo);
//    wchar_t* pSymName = 0;
//    if (!SymGetTypeInfo(hProcess, BaseOfDll, pSymInfo->TypeIndex, TI_GET_SYMNAME, &pSymName)) {
//
//    }
//    wprintf(L"%p %4u %s 0x%d %d\n",
//        pSymInfo->Address, pSymInfo->Flags, pSymInfo->Name, pSymInfo->Flags, pSymInfo->SizeOfStruct);
//    
//    DWORD childrencount = 0;
//    if (SymGetTypeInfo(hProcess, BaseOfDll, pSymInfo->TypeIndex, TI_GET_CHILDRENCOUNT, &childrencount)) {
//
//    }
//    else {
//        printf("error:%d,%s\n", GetLastError(), GetLastErrorAsString().c_str());
//    }
//
//    int FindChildrenSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrencount * sizeof(ULONG);
//
//    TI_FINDCHILDREN_PARAMS* pFC = (TI_FINDCHILDREN_PARAMS*)_alloca(FindChildrenSize);
//    memset(pFC, 0, FindChildrenSize);
//
//    pFC->Count = childrencount;
//    if (SymGetTypeInfo(hProcess, BaseOfDll, pSymInfo->TypeIndex, TI_FINDCHILDREN, pFC)) {
//
//    }
//    else {
//        printf("error:%d,%s\n", GetLastError(), GetLastErrorAsString().c_str());
//    }
//
//    for (int i = pFC->Start; i < pFC->Count;i++) {
//        wchar_t* pSymName = 0;
//        if (!SymGetTypeInfo(hProcess, BaseOfDll, pFC->ChildId[i], TI_GET_SYMNAME, &pSymName)) {
//
//        }
//        else {
//            printf("error:%d,%s\n", GetLastError(), GetLastErrorAsString().c_str());
//        }
//        GlobalFree(&pSymName);
//    }
//    return TRUE;
//}
//
//BOOL CALLBACK EnumTypes(
//    PSYMBOL_INFO pSymInfo,
//    ULONG SymbolSize,
//    PVOID UserContext
//) {
//    UNREFERENCED_PARAMETER(UserContext);
//
//    wprintf(L"%p %4u %s %d\n",
//        pSymInfo->Address, SymbolSize, pSymInfo->Name, pSymInfo->SizeOfStruct);
//    return TRUE;
//}
//
//BOOL CALLBACK PenumloadedModules(
//    PCWSTR ModuleName,
//    ULONG64 ModuleBase,
//    ULONG ModuleSize,
//    PVOID UserContext
//)
//{
//    UNREFERENCED_PARAMETER(UserContext);
//    wprintf(L"%s %p\n", ModuleName, ModuleBase);
//    return TRUE;
//}
//void test5()
//{
//    SymSetOptions(0x30337);
//    hProcess = GetCurrentProcess();
//    
//    wchar_t* Mask = (wchar_t*)L"*";
//    BOOL status;
//
//    status = SymInitialize(hProcess,NULL,TRUE);
//    if (status == FALSE)
//    {
//        return;
//    }
//
//    BaseOfDll = SymLoadModule64(hProcess,
//        NULL,
//        "C:\\Windows\\System32\\ntdll.dll",
//        NULL,
//        NULL,
//        0);
//    if (BaseOfDll == 0)
//    {
//        SymCleanup(hProcess);
//        return;
//    }
//    
//    if (SymEnumSymbols(hProcess,     // Process handle from SymInitialize.
//        BaseOfDll,   // Base address of module.
//        Mask,        // Name of symbols to match.
//        EnumSymProc, // Symbol handler procedure.
//        NULL))       // User context.
//    {
//        // SymEnumSymbols succeeded
//    }
//    else
//    {
//        // SymEnumSymbols failed
//        printf("SymEnumSymbols failed: %d\n", GetLastError());
//    }
//
//
//    SymCleanup(hProcess);
//}
//
//BOOL
//CALLBACK
//SymRegisterCallbackProc64(
//    __in HANDLE hProcess,
//    __in ULONG ActionCode,
//    __in_opt ULONG64 CallbackData,
//    __in_opt ULONG64 UserContext
//)
//{
//    UNREFERENCED_PARAMETER(hProcess);
//    UNREFERENCED_PARAMETER(UserContext);
//
//    PIMAGEHLP_CBA_EVENT evt;
//
//    // If SYMOPT_DEBUG is set, then the symbol handler will pass
//    // verbose information on its attempt to load symbols.
//    // This information be delivered as text strings.
//
//    switch (ActionCode)
//    {
//    case CBA_EVENT:
//        evt = (PIMAGEHLP_CBA_EVENT)CallbackData;
//        _tprintf(_T("%s"), (PTSTR)evt->desc);
//        break;
//
//        // CBA_DEBUG_INFO is the old ActionCode for symbol spew.
//        // It still works, but we use CBA_EVENT in this example.
//#if 0
//    case CBA_DEBUG_INFO:
//        _tprintf(_T("%s"), (PTSTR)CallbackData);
//        break;
//#endif
//
//    default:
//        // Return false to any ActionCode we don't handle
//        // or we could generate some undesirable behavior.
//        return FALSE;
//    }
//
//    return TRUE;
//}
//
//// Main code.
//BOOL CALLBACK mycallback(PSYMBOL_INFO pSymInfo, ULONG, PVOID) {
//    wprintf(L"%s\n", pSymInfo->Name);
//    return true;
//}
//int __cdecl
//test6()
//{
//    BOOL status;
//    int rc = -1;
//    HANDLE hProcess;
//    DWORD64 module;
//
//
//    // If we want to se debug spew, we need to set this option.
//
//    // We are not debugging an actual process, so lets use a placeholder
//    // value of 1 for hProcess just to ID these calls from any other
//    // series we may want to load.  For this simple case, anything will do.
//    SymSetOptions(SYMOPT_DEBUG);
//    hProcess = (HANDLE)1;
//
//    // Initialize the symbol handler.  No symbol path.  
//    // Just let dbghelp use _NT_SYMBOL_PATH
//
//    status = SymInitialize(hProcess, NULL, false);
//    if (!status)
//    {
//        _tprintf(_T("Error 0x%x calling SymInitialize.\n"), GetLastError());
//        return rc;
//    }
//
//    // Now register our callback.
//    wchar_t* dll = (wchar_t*)L"C:\\Windows\\System32\\ntoskrnl.exe";
//    status = SymRegisterCallback64(hProcess, SymRegisterCallbackProc64, NULL);
//    if (!status)
//    {
//        _tprintf(_T("Error 0x%x calling SymRegisterCallback64.\n"), GetLastError());
//        goto cleanup;
//    }
//
//    // Go ahead and load a module for testing.
//    
//    module = SymLoadModuleEx(hProcess,  // our unique id
//        NULL,      // no open file handle to image
//        dll,   // name of image to load
//        NULL,      // no module name - dbghelp will get it
//        0,         // no base address - dbghelp will get it
//        0,         // no module size - dbghelp will get it
//        NULL,      // no special MODLOAD_DATA structure
//        0);        // flags
//    if (!module)
//    {
//        _tprintf(_T("Error 0x%x calling SymLoadModuleEx.\n"), GetLastError());
//        goto cleanup;
//    }
//
//    SymEnumTypesByName(hProcess, (ULONG64)module, L"*!_EP*", mycallback, 0);
//    rc = 0;
//
//cleanup:
//    SymCleanup(hProcess);
//
//    return rc;
//}
//
//
//int test7() {
//    SymSetOptions(0x30337);
//    hProcess = GetCurrentProcess();
//
//    wchar_t* Mask = (wchar_t*)L"*";
//    BOOL status;
//
//    status = SymInitialize(hProcess, NULL, TRUE);
//    if (status == FALSE)
//    {
//        return 0;
//    }
//
//    BaseOfDll = SymLoadModule64(hProcess,
//        NULL,
//        "C:\\Windows\\System32\\ntdll.dll",
//        NULL,
//        NULL,
//        0);
//    if (BaseOfDll == 0)
//    {
//        SymCleanup(hProcess);
//        return 0;
//    }
//
//    SymEnumTypesByName(hProcess, (ULONG64)BaseOfDll, L"*!_R*", mycallback, 0);
//
//
//    SymCleanup(hProcess);
//    return 0;
//}
//
//
//
//#include <atlbase.h>
//#include <atlstr.h>
//#include <iostream>
//#include <string>
//using namespace std;
//
//
//#define BUFFER_SIZE 0x10240  
//
//
//int  test8()
//{
//    HKEY hKey;
//    DWORD dwType;
//    wchar_t valueBuf[BUFFER_SIZE];
//    TCHAR dllName[BUFFER_SIZE];
//    DWORD dwSize;
//
//
//    // Name of the event log.   
//    LPCTSTR logName = TEXT_STRING("application");
//    DWORD fm_flags = 0;
//    HANDLE h;
//    EVENTLOGRECORD* pevlr;
//    BYTE bBuffer[BUFFER_SIZE];
//    DWORD dwRead, dwNeeded;
//    LPCTSTR lpSourceName;
//
//    /* Flags for format event */
//    fm_flags |= FORMAT_MESSAGE_FROM_HMODULE;
//    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
//    fm_flags |= FORMAT_MESSAGE_FROM_SYSTEM;
//
//    // Step 1: ---------------------------------------------------------   
//    // Open the event log. ---------------------------------------------   
//    h = OpenEventLog(NULL, logName);
//    if (h == NULL)
//    {
//        std::wcout << L"Could not open the event log." << std::endl;
//        return 0;
//    }
//
//    // Step 2: ---------------------------------------------------------   
//    // Initialize the event record buffer. -----------------------------   
//    pevlr = (EVENTLOGRECORD*)&bBuffer;
//
//    // Step 3: ---------------------------------------------------------   
//    // When the event log is opened, the position of the file pointer   
//    // is at the beginning of the log. Read the event log records   
//    // sequentially until the last record has been read.   
//    if (ReadEventLog(h,                // Event log handle   
//        EVENTLOG_BACKWARDS_READ |          // Reads forward   
//        EVENTLOG_SEQUENTIAL_READ,         // Sequential read   
//        0,                                // Ignored for sequential read   
//        pevlr,                            // Pointer to buffer   
//        BUFFER_SIZE,                      // Size of buffer   
//        &dwRead,                          // Number of bytes read   
//        &dwNeeded))                       // Bytes in the next record   
//    {
//        while (dwRead > 0)
//        {
//            // Get the event source name.   
//            lpSourceName = (LPCTSTR)((LPBYTE)pevlr + sizeof(EVENTLOGRECORD));
//            CString strKey;
//            strKey.Format(TEXT_STRING("SYSTEM\\CURRENTCONTROLSET\\SERVICES\\EVENTLOG\\%s\\%s"), logName, lpSourceName);
//            if (RegOpenKey(HKEY_LOCAL_MACHINE, strKey, &hKey) == ERROR_SUCCESS) {
//                dwType = REG_EXPAND_SZ;
//                dwSize = sizeof(valueBuf);
//                if (RegQueryValueExW(hKey, L"EventMessageFile", 0, &dwType, (unsigned char*)&valueBuf, &dwSize) != ERROR_SUCCESS) {
//                    printf("Some error occurred!\n");
//                }
//                ExpandEnvironmentStringsW(valueBuf, dllName, dwSize);
//            }
//            RegCloseKey(hKey);
//
//            // Step 4: ---------------------------------------------------------   
//           // Load the message DLL file. --------------------------------------   
//            HMODULE hResources = NULL;
//            hResources = LoadLibraryEx(dllName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
//
//            // Print the information if the event source and the message   
//            // match the parameters   
//            LPTSTR pMessage = NULL;
//            int num = 0;
//            // Step 5: ----------------------------------------------   
//            // Retrieve the message string. -------------------------   
//            num = FormatMessage(
//                fm_flags, // Format of message   
//                hResources,                    // Handle to the DLL file   
//                pevlr->EventID,              // Event message identifier   
//                MAKELCID(LANG_NEUTRAL, SUBLANG_DEFAULT),
//                (LPTSTR)&pMessage,
//                0,
//                NULL);                       // Array of insert values   
//
//            FreeLibrary(hResources);
//
//            if (pMessage)
//            {
//                wprintf(L"%s\n", (LPTSTR)pMessage);
//                LocalFree(pMessage);
//            }
//
//            dwRead -= pevlr->Length;
//            pevlr = (EVENTLOGRECORD*)((LPBYTE)pevlr + pevlr->Length);
//        }
//    }
//
//    // Step 6: -------------------------------------------------------------   
//    // Close the event log.   
//    CloseEventLog(h);
//
//    return 0;
//}
//
//#include <windows.h>
//#include <sddl.h>
//#include <stdio.h>
//#include <winevt.h>
//
//#pragma comment(lib, "wevtapi.lib")
//
//#define ARRAY_SIZE 10
//#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call
//
//// The structured XML query.
//#define QUERY \
//    L"<QueryList>" \
//    L"  <Query Path='application'>" \
//    L"    <Select Path=\"Application\">*</Select>" \
//    L"  </Query>" \
//    L"</QueryList>"
//
//DWORD PrintQueryStatuses(EVT_HANDLE hResults);
//DWORD GetQueryStatusProperty(EVT_QUERY_PROPERTY_ID Id, EVT_HANDLE hResults, PEVT_VARIANT& pProperty);
//DWORD PrintResults(EVT_HANDLE hResults);
//DWORD PrintEvent(EVT_HANDLE hEvent);  // Shown in the Rendering Events topic
//
//void test9(void)
//{
//    DWORD status = ERROR_SUCCESS;
//    EVT_HANDLE hResults = NULL;
//
//    hResults = EvtQuery(NULL, NULL, QUERY, EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
//    if (NULL == hResults)
//    {
//        // Handle error.
//        goto cleanup;
//    }
//
//    // Print the status of each query. If all the queries succeeded,
//    // print the events in the result set. The status can be
//    // ERROR_EVT_CHANNEL_NOT_FOUND or ERROR_EVT_INVALID_QUERY among others.
//    if (ERROR_SUCCESS == PrintQueryStatuses(hResults))
//        PrintResults(hResults);
//
//cleanup:
//
//    if (hResults)
//        EvtClose(hResults);
//
//}
//
//DWORD PrintQueryStatuses(EVT_HANDLE hResults)
//{
//    DWORD status = ERROR_SUCCESS;
//    PEVT_VARIANT pPaths = NULL;
//    PEVT_VARIANT pStatuses = NULL;
//
//    wprintf(L"List of channels/logs that were queried and their status\n\n");
//
//    if (status = GetQueryStatusProperty(EvtQueryNames, hResults, pPaths))
//        goto cleanup;
//
//    if (status = GetQueryStatusProperty(EvtQueryStatuses, hResults, pStatuses))
//        goto cleanup;
//
//    for (DWORD i = 0; i < pPaths->Count; i++)
//    {
//        wprintf(L"%s (%lu)\n", pPaths->StringArr[i], pStatuses->UInt32Arr[i]);
//        status += pStatuses->UInt32Arr[i];
//    }
//
//cleanup:
//
//    if (pPaths)
//        free(pPaths);
//
//    if (pStatuses)
//        free(pStatuses);
//
//    return status;
//}
//
//
//// Get the list of paths specified in the query or the list of status values 
//// for each path.
//DWORD GetQueryStatusProperty(EVT_QUERY_PROPERTY_ID Id, EVT_HANDLE hResults, PEVT_VARIANT& pProperty)
//{
//    DWORD status = ERROR_SUCCESS;
//    DWORD dwBufferSize = 0;
//    DWORD dwBufferUsed = 0;
//
//    if (!EvtGetQueryInfo(hResults, Id, dwBufferSize, pProperty, &dwBufferUsed))
//    {
//        status = GetLastError();
//        if (ERROR_INSUFFICIENT_BUFFER == status)
//        {
//            dwBufferSize = dwBufferUsed;
//            pProperty = (PEVT_VARIANT)malloc(dwBufferSize);
//            if (pProperty)
//            {
//                EvtGetQueryInfo(hResults, Id, dwBufferSize, pProperty, &dwBufferUsed);
//            }
//            else
//            {
//                wprintf(L"realloc failed\n");
//                status = ERROR_OUTOFMEMORY;
//                goto cleanup;
//            }
//        }
//
//        if (ERROR_SUCCESS != (status = GetLastError()))
//        {
//            wprintf(L"EvtGetQueryInfo failed with %d\n", GetLastError());
//            goto cleanup;
//        }
//    }
//
//cleanup:
//
//    return status;
//}
//
//DWORD PrintResults(EVT_HANDLE hResults)
//{
//    DWORD status = ERROR_SUCCESS;
//    EVT_HANDLE hEvents[ARRAY_SIZE];
//    DWORD dwReturned = 0;
//
//    while (true)
//    {
//        // Get a block of events from the result set.
//        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
//        {
//            if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
//            {
//                wprintf(L"EvtNext failed with %lu\n", status);
//            }
//
//            goto cleanup;
//        }
//
//        // For each event, call the PrintEvent function which renders the
//        // event for display. PrintEvent is shown in RenderingEvents.
//        for (DWORD i = 0; i < dwReturned; i++)
//        {
//            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
//            {
//                EvtClose(hEvents[i]);
//                hEvents[i] = NULL;
//            }
//            else
//            {
//                goto cleanup;
//            }
//        }
//    }
//
//cleanup:
//
//    for (DWORD i = 0; i < dwReturned; i++)
//    {
//        if (NULL != hEvents[i])
//            EvtClose(hEvents[i]);
//    }
//
//    return status;
//}
//
//DWORD PrintEvent(EVT_HANDLE hEvent)
//{
//    DWORD status = ERROR_SUCCESS;
//    DWORD dwBufferSize = 0;
//    DWORD dwBufferUsed = 0;
//    DWORD dwPropertyCount = 0;
//    LPWSTR pRenderedContent = NULL;
//
//    // The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
//    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
//    {
//        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
//        {
//            dwBufferSize = dwBufferUsed;
//            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
//            if (pRenderedContent)
//            {
//                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
//            }
//            else
//            {
//                wprintf(L"malloc failed\n");
//                status = ERROR_OUTOFMEMORY;
//                goto cleanup;
//            }
//        }
//
//        if (ERROR_SUCCESS != (status = GetLastError()))
//        {
//            wprintf(L"EvtRender failed with %d\n", GetLastError());
//            goto cleanup;
//        }
//    }
//
//    wprintf(L"\n\n%s", pRenderedContent);
//
//cleanup:
//
//    if (pRenderedContent)
//        free(pRenderedContent);
//
//    return status;
//}

#include <Windows.h>

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005

// Create/open flags

#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_CREATE_TREE_CONNECTION 0x00000080

#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_OPEN_FOR_RECOVERY 0x00000400
#define FILE_RANDOM_ACCESS 0x00000800

#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000

#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
void ReadMft(PCWSTR szVolume)
{
    HANDLE hVolume = CreateFileW(szVolume, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_OPEN_FOR_BACKUP_INTENT, 0);

    if (hVolume != INVALID_HANDLE_VALUE)
    {
        NTFS_VOLUME_DATA_BUFFER nvdb;

        OVERLAPPED ov = {};

        if (DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, 0, 0, &nvdb, sizeof(nvdb), 0, &ov))
        {
            NTFS_FILE_RECORD_INPUT_BUFFER nfrib;

            nfrib.FileReferenceNumber.QuadPart = nvdb.MftValidDataLength.QuadPart / nvdb.BytesPerFileRecordSegment - 1;

            ULONG cb = __builtin_offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer[nvdb.BytesPerFileRecordSegment]);

            PNTFS_FILE_RECORD_OUTPUT_BUFFER pnfrob = (PNTFS_FILE_RECORD_OUTPUT_BUFFER)malloc(cb);

            do
            {
                if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_FILE_RECORD,
                    &nfrib, sizeof(nfrib), pnfrob, cb, 0, &ov))
                {
                    break;
                }

                // pnfrob->FileRecordBuffer :
                // here pnfrob->FileReferenceNumber FileRecord

            } while (0 <= (nfrib.FileReferenceNumber.QuadPart = pnfrob->FileReferenceNumber.QuadPart - 1));

            //ReadMft2(szVolume, hVolume, &nvdb);
        }

        CloseHandle(hVolume);
    }
}
#include <esent.h>
#include <stdio.h>
#include <string>
int main() {
    JET_HANDLE handle;
    unsigned long pulLow;
    unsigned long pulHigh;
    std::string s = "C:\\Users\\nsfocus\\Desktop\\test\\srudb.dat\0";
    JET_ERR status = JetOpenFileA(s.c_str(), &handle, &pulLow, &pulHigh);
    if (status != 0) {
        printf("error\n");
    }

    return 0;

}