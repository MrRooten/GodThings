#include "headers.h"
#include "GTMemory.h"
#include "GTProcess.h"
NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
) {
	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DeviceObjectName;
	UNICODE_STRING DeviceLinkName;
	ULONG i;

	DriverObject->DriverUnload = DriverUnload;
	DbgPrint("Angel Loaded Successfuly\r\n");
	RtlInitUnicodeString(&DeviceObjectName, DEVICE_OBJECT_NAME);

	Status = IoCreateDevice(DriverObject, NULL,
		&DeviceObjectName,
		FILE_DEVICE_UNKNOWN,
		0, FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("Angel Create Device Failed:%p\r\n", Status);
		return Status;
	}

	RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);

	Status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceObjectName);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("Angel Create Link File Failed:%p\r\n", Status);
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = PassThroughDispatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlThroughDispatch;
	return Status;
}

NTSTATUS PassThroughDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ControlThroughDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = 0;
	PIO_STACK_LOCATION stackLocation;
	PFILE_OBJECT fileObject;
	PVOID originalInput;
	ULONG inputLength;
	ULONG ioControlCode;
	KPROCESSOR_MODE accessMode;
	UCHAR capturedInput[16 * sizeof(ULONG_PTR)];
	PVOID capturedInputPointer;

#define VERIFY_INPUT_LENGTH \
    do { \
        /* Ensure at compile time that our local buffer fits this particular call. */ \
        C_ASSERT(sizeof(*input) <= sizeof(capturedInput)); \
        \
        if (inputLength != sizeof(*input)) \
        { \
            status = STATUS_INFO_LENGTH_MISMATCH; \
            goto ControlEnd; \
        } \
    } while (0)

	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	fileObject = stackLocation->FileObject;


	originalInput = stackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
	inputLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
	ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
	accessMode = Irp->RequestorMode;

	// Make sure we actually have input if the input length is non-zero.
	if (inputLength != 0 && !originalInput)
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		goto ControlEnd;
	}

	// Make sure the caller isn't giving us a huge buffer. If they are, it can't be correct because
	// we have a compile-time check that makes sure our buffer can store the arguments for all the
	// calls.
	if (inputLength > sizeof(capturedInput))
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		goto ControlEnd;
	}

	// Probe and capture the input buffer.
	if (accessMode != KernelMode)
	{
		__try
		{
			ProbeForRead(originalInput, inputLength, sizeof(UCHAR));
			memcpy(capturedInput, originalInput, inputLength);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
			goto ControlEnd;
		}
	}
	else
	{
		memcpy(capturedInput, originalInput, inputLength);
	}

	capturedInputPointer = capturedInput; // avoid casting below
	switch (ioControlCode) {
	case IOCTL_GTCTL_METHOD_READ_MEMORY:{
		struct
		{
			PVOID BaseAddress;
			PVOID Buffer;
			SIZE_T BufferSize;
			PSIZE_T NumberOfBytesRead;
		} *input = capturedInputPointer;

		VERIFY_INPUT_LENGTH;

		status = GTReadVirtualMemory(
			input->BaseAddress,
			input->Buffer,
			input->BufferSize,
			input->NumberOfBytesRead,
			accessMode
		);
		break;
	}
	case IOCTL_GTCTL_METHOD_WRITE_MEMORY:{

		break;
	}
	case IOCTL_GTCTL_METHOD_OPEN_PROCESS: {
		DbgPrint("GTOpenProcess\n");
		struct {
			PHANDLE hHandle;
			unsigned long accessRight;
			unsigned long processId;
		} *input = capturedInputPointer;

		//VERIFY_INPUT_LENGTH;
		status = GTOpenProcess(
			input->hHandle,
			input->accessRight,
			input->processId,
			accessMode
		);

		break;
	}
	default:
		break;
	}
ControlEnd:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  DeviceLinkName;
	PDEVICE_OBJECT  v1 = NULL;
	PDEVICE_OBJECT  DeleteDeviceObject = NULL;

	RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
	IoDeleteSymbolicLink(&DeviceLinkName);

	DeleteDeviceObject = DriverObject->DeviceObject;
	while (DeleteDeviceObject != NULL)
	{
		v1 = DeleteDeviceObject->NextDevice;
		IoDeleteDevice(DeleteDeviceObject);
		DeleteDeviceObject = v1;
	}
}