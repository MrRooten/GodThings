#include "ProcessUtils.h"
#include "PrivilegeUtils.h"

HANDLE GTOpenProcess(
	DWORD ProcessId,
	DWORD AccessRight
) {
	DWORD status;
	HANDLE hProcess = NULL;
	HANDLE resHandle = NULL;
	do {
		if (HasDriver() == TRUE) {
			//printf("Process in kernel\n");
			struct {
				PHANDLE hHandle;
				DWORD accessRight;
				DWORD processId;
			} input;
			input.accessRight = AccessRight;
			input.processId = ProcessId;
			input.hHandle = new HANDLE;
			//printf("handle:%p,%x,%d", input.hHandle, input.accessRight, input.processId);
			status = GTDeviceIoControl(
				&input,
				sizeof input,
				IOCTL_GTCTL_METHOD_OPEN_PROCESS
			);
			
			
			hProcess = *input.hHandle;
			return hProcess;
		}
	} while (0);
	hProcess = OpenProcess(AccessRight, FALSE, ProcessId);
	return hProcess;
}