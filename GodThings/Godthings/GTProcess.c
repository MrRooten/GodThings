#include "GTProcess.h"

NTSTATUS GTOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UINT32 ProcessId,
    _In_ KPROCESSOR_MODE AccessMode
) {
    
    NTSTATUS status;
    CLIENT_ID clientId;
    PEPROCESS process;
    PETHREAD thread;
    HANDLE processHandle;

    PAGED_CODE();

    process = NULL;

    if (AccessMode != KernelMode)
    {
        __try
        {

            ProbeForWrite(ProcessHandle, sizeof(HANDLE), sizeof(HANDLE));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }

    // Use the thread ID if it was specified.
    status = PsLookupProcessByProcessId(ProcessId, &process);
    

    if (!NT_SUCCESS(status))
    {
        process = NULL;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    // Always open in KernelMode to skip ordinary access checks.
    status = ObOpenObjectByPointer(
        process,
        0,
        NULL,
        DesiredAccess,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (NT_SUCCESS(status))
    {
        if (AccessMode != KernelMode)
        {
            __try
            {
                *ProcessHandle = processHandle;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }
        }
        else
        {
            *ProcessHandle = processHandle;
        }
    }

CleanupExit:
    if (process)
    {
        ObDereferenceObject(process);
    }

    return status;
}