#pragma once
#include "headers.h"
/*
Accept: Addr[64bit]|Size[16bit]
Return: Error:Error message if fails With Error NTStatus
		Address[64bit] with Success NTStatus
*/
NTSTATUS GTReadVirtualMemory(
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead,
    _In_ KPROCESSOR_MODE AccessMode
);

NTSTATUS GTWriteVirtualMemory(
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize
    );

