#include "PrivilegeUtils.h"

BOOL HasPrivilege(std::wstring privilege) {
	HANDLE hToken = GetCurrentProcessToken();
	if (pPrivileges == NULL) {
		DWORD size;
		pPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(GPTR, 1024);
		if (pPrivileges == NULL) {
			return FALSE;
		}
		GetTokenInformation(hToken, TokenPrivileges, pPrivileges, 1024, &size);
		for (int i = 0; i < pPrivileges->PrivilegeCount; i++) {
			WCHAR _tmp[100];
			DWORD dwSize = 100;
			LookupPrivilegeNameW(NULL, &pPrivileges->Privileges[i].Luid, _tmp, &dwSize);
			privilegesSet.insert(_tmp);
		}
	}
	if (privilegesSet.count(privilege) > 0) {
		return TRUE;
	}

	return FALSE;
}


