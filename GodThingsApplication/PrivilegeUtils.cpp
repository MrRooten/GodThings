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
		for (DWORD i = 0; i < pPrivileges->PrivilegeCount; i++) {
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

BOOL DebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		//std::cerr << "Failed to open process token." << std::endl;
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		//std::cerr << "Failed to look up privilege value." << std::endl;
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		//std::cerr << "Failed to adjust token privileges." << std::endl;
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		//std::cerr << "Failed to assign all privileges." << std::endl;
		return FALSE;
	}

	return TRUE;
}


