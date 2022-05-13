#pragma once
#include "public.h"
#include <string>

typedef VOID (*EntryCallback)(std::wstring entry);

VOID GetLogonAutoRuns(EntryCallback callback);

VOID GetDriverAutoRuns(EntryCallback callback);

VOID GetBootAutoRuns(EntryCallback callback);

VOID GetServiceAutoRuns(EntryCallback callback);

