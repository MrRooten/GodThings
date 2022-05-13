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

#include <windows.h> 
#include <stdio.h> 
#include <tchar.h>
#include <strsafe.h>
#include <thread>
#define BUFSIZE 512

DWORD WINAPI InstanceThread(LPVOID);
VOID GetAnswerToRequest(LPSTR, LPSTR, LPDWORD);

int _tmain(VOID)
{
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
    LPCSTR lpszPipename = "\\\\.\\pipe\\gtpipe";

    // The main loop creates an instance of the named pipe and 
    // then waits for a client to connect to it. When the client 
    // connects, a thread is created to handle communications 
    // with that client, and this loop is free to wait for the
    // next client connect request. It is an infinite loop.

    for (;;)
    {
        printf("\nPipe Server: Main thread awaiting client connection on %s\n", lpszPipename);
        hPipe = CreateNamedPipeA(
            lpszPipename,             // pipe name 
            PIPE_ACCESS_DUPLEX,       // read/write access 
            PIPE_TYPE_MESSAGE |       // message type pipe 
            PIPE_READMODE_MESSAGE |   // message-read mode 
            PIPE_WAIT,                // blocking mode 
            PIPE_UNLIMITED_INSTANCES, // max. instances  
            BUFSIZE,                  // output buffer size 
            BUFSIZE,                  // input buffer size 
            0,                        // client time-out 
            NULL);                    // default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            _tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
            return -1;
        }

        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (fConnected)
        {
            printf("Client connected, creating a processing thread.\n");

            // Create a thread for this client. 
            hThread = CreateThread(
                NULL,              // no security attribute 
                0,                 // default stack size 
                InstanceThread,    // thread proc
                (LPVOID)hPipe,    // thread parameter 
                0,                 // not suspended 
                &dwThreadId);      // returns thread ID 
            if (hThread == NULL)
            {
                _tprintf(TEXT("CreateThread failed, GLE=%d.\n"), GetLastError());
                return -1;
            }
            else CloseHandle(hThread);
        }
        else
            // The client could not connect, so close the pipe. 
            CloseHandle(hPipe);
    }

    return 0;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
    HANDLE hHeap = GetProcessHeap();
    CHAR* pchRequest = (CHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(CHAR));
    CHAR* pchReply = (CHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(CHAR));

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;

    // Do some extra error checking since the app will keep running even if this
    // thread fails.

    if (lpvParam == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }

    if (pchRequest == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        return (DWORD)-1;
    }

    if (pchReply == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }

    // Print verbose messages. In production code, this should be for debugging only.
    printf("InstanceThread created, receiving and processing messages.\n");

    // The thread's parameter is a handle to a pipe object instance. 

    hPipe = (HANDLE)lpvParam;

    // Loop until done reading
    while (1)
    {
        // Read client requests from the pipe. This simplistic code only allows messages
        // up to BUFSIZE characters in length.
        fSuccess = ReadFile(
            hPipe,        // handle to pipe 
            pchRequest,    // buffer to receive data 
            BUFSIZE * sizeof(TCHAR), // size of buffer 
            &cbBytesRead, // number of bytes read 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbBytesRead == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                _tprintf(TEXT("InstanceThread: client disconnected.\n"));
            }
            else
            {
                _tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError());
            }
            break;
        }

        // Process the incoming message.
        GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);

        // Write the reply to the pipe. 
        fSuccess = WriteFile(
            hPipe,        // handle to pipe 
            pchReply,     // buffer to write from 
            cbReplyBytes, // number of bytes to write 
            &cbWritten,   // number of bytes written 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbReplyBytes != cbWritten)
        {
            printf("InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
            break;
        }
    }

    // Flush the pipe to allow the client to read the pipe's contents 
    // before disconnecting. Then disconnect the pipe, and close the 
    // handle to this pipe instance. 

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    HeapFree(hHeap, 0, pchRequest);
    HeapFree(hHeap, 0, pchReply);

    printf("InstanceThread exiting.\n");
    return 1;
}

VOID GetAnswerToRequest(LPSTR pchRequest,
    LPSTR pchReply,
    LPDWORD pchBytes)
    // This routine is a simple function to print the client request to the console
    // and populate the reply buffer with a default data string. This is where you
    // would put the actual client request processing code that runs in the context
    // of an instance thread. Keep in mind the main thread will continue to wait for
    // and receive other client connections while the instance thread is working.
{
    printf("Client Request String:\"%s\"\n", pchRequest);
    Sleep(2000);

    // Check the outgoing message to make sure it's not too long for the buffer.
    if (FAILED(StringCchCopyA(pchReply, BUFSIZE, "default answer from server")))
    {
        *pchBytes = 0;
        pchReply[0] = 0;
        printf("StringCchCopy failed, no outgoing message.\n");
        return;
    }
    *pchBytes = (strlen(pchReply) + 1) * sizeof(CHAR);
}