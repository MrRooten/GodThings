#pragma once
#ifndef _ACCOUNT_H
#define _ACCOUNT_H
#include "public.h"
#include "lmaccess.h"
#include "utils.h"
#include <vector>
#include <string>
#pragma comment(lib, "netapi32.lib")
class AccountInfo {
	bool isSidInit = false;
	SID* sid = NULL;

	WCHAR* domainName = NULL;
public:
	DWORD Initialize(PUSER_INFO_3 userInfo);
	std::wstring userName;
	GTWString UserName();
	std::wstring comment;
	GTWString& GetComment();
	DWORD passwordAge;
	GTTime GetPasswordTime();
	DWORD privilege;
	DWORD GetPrivilege();
	GTWString GetPrivilegeAsString();
	std::wstring homeDir;
	DWORD flags;
	std::wstring scriptPath;
	DWORD authFlags;
	std::wstring fullName;
	std::wstring usrComment;
	std::wstring params;
	std::wstring workstations;
	DWORD lastLogon;
	GTTime GetLastLogon();
	DWORD lastLogoff;
	GTTime GetLastLogoff();
	DWORD acctExpires;
	DWORD maxStorage;
	DWORD unitsPerWeek;
	BytesBuffer logonHours;
	DWORD badPasswordCount;
	DWORD numLogons;
	DWORD GetLastLogNum();
	std::wstring logonServer;
	GTWString& GetLogonServer();
	DWORD countryCode;
	DWORD codePage;
	DWORD userId;
	DWORD GetUserId();
	DWORD primaryGroupId;
	std::wstring profile;
	GTWString& GetProfile();
	std::wstring homeDirDrive;
	SID* GetSid();
	DWORD passwordExpired;
	~AccountInfo();
};

class AccountInfoManager {
private:
	std::vector<AccountInfo*> _users;
public:
	DWORD Initialize();
	std::vector<AccountInfo*> GetAccountList();
	AccountInfo* GetAccountInfo(std::wstring userName);
	std::vector<AccountInfo*> GetAccountsByGroup(std::wstring groupName);
	~AccountInfoManager();
};

#endif 