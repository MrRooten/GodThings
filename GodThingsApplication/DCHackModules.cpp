#include "DCHackModules.h"
#include "LDAPUtils.h"
#include "StringUtils.h"
UnconstrainedDelegation::UnconstrainedDelegation() {
	this->Name = L"UnconstrainedDelegation";
	this->Path = L"DCHack";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Try to detect Unconstrained Delegation";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* UnconstrainedDelegation::ModuleRun() {
	ResultSet* res = new ResultSet();
	PWSTR filter = (PWSTR)L"(|(&(samAccountType=805306368)(msds-allowedtodelegateto=*))(&(ObjectClass=computer)(mS-DS-CreatorSID=*)))";
	PWCHAR pMyAttributes[] = { (PWCHAR)L"cn", (PWCHAR)L"msds-allowedtodelegateto", (PWCHAR)L"mS-DS-CreatorSID", NULL };
	auto domain = StringUtils::s2ws(this->args["domain"]);
	int port = LDAP_PORT;
	if (this->args.count("port") != 0) {
		port = stoi(args["port"]);
	}
	if (this->args.count("username") == 0 || this->args.count("password") == 0) {
		res->SetErrorMessage("Must Set username and password");
		return res;
	}
	GTWString username = StringUtils::s2ws(this->args["username"]);
	GTWString password = StringUtils::s2ws(this->args["password"]);

	LDAPSession session((GTRawWString)domain.c_str(), port);
	LOG_INFO(L"Initalize LDAP session...");
	auto result = session.Initialize();
	if (!result.Ok()) {
		LOG_ERROR(result.GetReason().c_str());
		return res;
	}
	LOG_INFO(L"Connecting LDAP server...");
	result = session.Connect();
	if (!result.Ok()) {
		LOG_ERROR(result.GetReason().c_str());
		return res;
	}

	LOG_INFO(L"Auth to LDAP server...");
	LDAPIdentity identity((GTRawWString)username.c_str(), (GTRawWString)domain.c_str(), (GTRawWString)password.c_str(), 0);
	result = session.Authenticate(&identity, LDAP_AUTH_NEGOTIATE);
	if (!result.Ok()) {
		LOG_ERROR(result.GetReason().c_str());
		return res;
	}

	LOG_INFO(L"Searching filter and attributes");
	result = session.Search(LDAP_SCOPE_SUBTREE, filter, pMyAttributes);
	if (!result.Ok()) {
		LOG_ERROR(result.GetReason().c_str());
		return res;
	}


	return res;
}
