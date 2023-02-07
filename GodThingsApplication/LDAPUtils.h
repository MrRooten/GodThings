#pragma once
#include "public.h"
#include "utils.h"
#include <string>
#include <Winldap.h>
class LDAPIdentity {
	GTWString username;
	GTWString password;
	GTWString domain;
	UINT32 flag;
public:
	LDAPIdentity(GTRawWString username,
		GTRawWString domain,
		GTRawWString password,
		UINT32 flag);

	SEC_WINNT_AUTH_IDENTITY_W GetIdentity();

};

class LDAPResult {
	LDAPMessage* message = NULL;
	DWORD errorCode = LDAP_SUCCESS;
public:
	LDAPResult();
	LDAPResult(DWORD errorCode);
	PLDAPMessage* GetMessageAddr();
	GTWString GetReason();
	BOOL Ok();
	VOID SetCode(DWORD errorCode);
	~LDAPResult();
};

class LDAPSession {
	GTWString host;
	ULONG port;
	LDAP* ldap = NULL;
public:
	LDAPSession(GTRawWString host, ULONG port);

	LDAPResult Initialize();

	LDAPResult SetOption(int key, void* value);

	LDAPResult Login();

	LDAPResult Authenticate(LDAPIdentity& identity,ULONG method);

	LDAPResult Search(ULONG scope, PWSTR filter, PWSTR* attrs);

	~LDAPSession();
};

GTWString GetLDAPErrorCodeAsString(ULONG code);