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
public:
	DWORD Initialize(PUSER_INFO_3 userInfo);
	std::wstring userName;
	std::wstring comment;
	DWORD passwordAge;
	DWORD privilege;
	std::wstring homeDir;
	DWORD flags;
	std::wstring scriptPath;
	DWORD authFlags;
	std::wstring fullName;
	std::wstring usrComment;
	std::wstring params;
	std::wstring workstations;
	DWORD lastLogon;
	DWORD lastLogoff;
	DWORD acctExpires;
	DWORD maxStorage;
	DWORD unitsPerWeek;
	BytesBuffer logonHours;
	DWORD badPasswordCount;
	DWORD numLogons;
	std::wstring logonServer;
	DWORD countryCode;
	DWORD codePage;
	DWORD userId;
	DWORD primaryGroupId;
	std::wstring profile;
	std::wstring homeDirDrive;
	DWORD passwordExpired;
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