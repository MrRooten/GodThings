#include "ntapi.h"

void* GetNativeProc(const CHAR* procName) {
    HINSTANCE hinstLib = LoadLibraryW(L"ntdll.dll");
	return GetProcAddress(
        hinstLib,
        procName);
}

void* GetAnyProc(const CHAR* mod, const CHAR* procName) {
    HINSTANCE hinstLib = LoadLibraryA(mod);
    return GetProcAddress(
        hinstLib,
        procName);
}
DWORD NtStatusHandler(NTSTATUS status) {
    if (RtlNtStatusToDosError == NULL) {
        RtlNtStatusToDosError = (pRtlNtStatusToDosError)GetNativeProc("RtlNtStatusToDosError");
    }
    SetLastError(RtlNtStatusToDosError(status));
    return GetLastError();
}