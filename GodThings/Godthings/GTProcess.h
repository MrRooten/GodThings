#pragma once
#include "headers.h"
NTSTATUS GTOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UINT32 ClientId,
    _In_ KPROCESSOR_MODE AccessMode
);