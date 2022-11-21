#include "PrivilegeUtils.h"
#include "sddl.h"
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

GTWString ConvertSidToUsername(const WCHAR* sid) {
	PSID out;
	if (!ConvertStringSidToSidW(sid, &out)) {
		return L"";
	}
	DWORD dwName = 100;
	WCHAR outName[100];
	DWORD dwDomain = 256;
	WCHAR outDomain[256];
	SID_NAME_USE use;
	if (!LookupAccountSidW(NULL,out, outName, &dwName, outDomain, &dwDomain, &use)) {
		return L"";
	}
	return outName;
}


