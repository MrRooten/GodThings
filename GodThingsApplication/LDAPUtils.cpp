#include "LDAPUtils.h"

LDAPIdentity::LDAPIdentity(GTRawWString username, GTRawWString domain, GTRawWString password, UINT32 flag) {
	this->username = username;
	this->domain = domain;
	this->password = password;
	this->flag = flag;
}

SEC_WINNT_AUTH_IDENTITY_W LDAPIdentity::GetIdentity() {
	SEC_WINNT_AUTH_IDENTITY_W ret = { 0 };
	ret.User = (USHORT*)this->username.c_str();
	ret.UserLength = (ULONG)this->username.length();
	ret.Password = (USHORT*)this->password.c_str();
	ret.PasswordLength = (ULONG)this->password.length();
	ret.Domain = (USHORT*)this->domain.c_str();
	ret.DomainLength = (ULONG)this->domain.length();

	return ret;
}

LDAPSession::LDAPSession(GTRawWString host, ULONG port) {
	this->host = host;
	this->port = port;
}

LDAPResult LDAPSession::Initialize() {
	this->ldap = ldap_initW((PWSTR)this->host.c_str(), port);
	if (this->ldap == NULL) {
		return GetLastError();
	}
	return 0;
}

LDAPResult LDAPSession::SetOption(int key,void* value) {
	auto ret = ldap_set_optionW(
		this->ldap,
		key,
		value
	);
	return LDAPResult(ret);
}

LDAPResult LDAPSession::Login() {
	auto ret = ldap_connect(this->ldap, NULL);
	return ret;
}

LDAPResult LDAPSession::Authenticate(LDAPIdentity& identity,ULONG method) {
	auto ret = ldap_bind_sW(
		this->ldap,
		(PWSTR)this->host.c_str(),
		(PWCHAR)&identity,
		method
	);

	return LDAPResult(ret);
}

LDAPResult LDAPSession::Search(ULONG scope, PWSTR filter, PWSTR* attrs) {
	LDAPResult ret;
	auto code = ldap_search_sW(
		this->ldap,
		(const PWSTR)this->host.c_str(),
		scope,
		filter,
		attrs,
		0,
		ret.GetMessageAddr()
	);

	if (code != LDAP_SUCCESS) {
		ret.SetCode(code);
	}

	return ret;
}

LDAPSession::~LDAPSession() {
	ldap_unbind_s(this->ldap);
}

LDAPResult::LDAPResult() {
}

LDAPResult::LDAPResult(DWORD errorCode) {
	this->errorCode = errorCode;
}

PLDAPMessage* LDAPResult::GetMessageAddr() {
	return &message;
}

GTWString LDAPResult::GetReason()
{
	return GTWString();
}

BOOL LDAPResult::Ok() {
	return this->errorCode == LDAP_SUCCESS;
}

VOID LDAPResult::SetCode(DWORD errorCode)
{
	return VOID();
}

LDAPResult::~LDAPResult() {
	if (message != NULL) {
		ldap_msgfree(message);
		message = NULL;
	}
}
