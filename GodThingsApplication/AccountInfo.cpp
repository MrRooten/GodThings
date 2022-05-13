#include "AccountInfo.h"
DWORD AccountInfo::Initialize(PUSER_INFO_3 userInfo) {
	if (userInfo == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	this->userName = userInfo->usri3_name;

	this->comment = userInfo->usri3_comment;
	this->passwordAge = userInfo->usri3_password_age;
	this->privilege = userInfo->usri3_priv;

	this->homeDir = userInfo->usri3_home_dir;
	this->flags = userInfo->usri3_flags;
	
	this->scriptPath = userInfo->usri3_script_path;

	
	this->authFlags = userInfo->usri3_auth_flags;

	this->fullName = userInfo->usri3_full_name;

	this->usrComment = userInfo->usri3_usr_comment;


	this->params = userInfo->usri3_parms;

	
	this->workstations = userInfo->usri3_workstations;

	this->lastLogon = userInfo->usri3_last_logon;
	this->lastLogoff = userInfo->usri3_last_logoff;
	this->acctExpires = userInfo->usri3_acct_expires;
	this->maxStorage = userInfo->usri3_max_storage;
	this->unitsPerWeek = userInfo->usri3_units_per_week;
	this->logonHours = (CHAR*)userInfo->usri3_logon_hours;
	this->badPasswordCount = userInfo->usri3_bad_pw_count;
	this->numLogons = userInfo->usri3_num_logons;

	this->logonServer = userInfo->usri3_logon_server;
	this->countryCode = userInfo->usri3_country_code;
	this->userId = userInfo->usri3_user_id;
	this->primaryGroupId = userInfo->usri3_primary_group_id;

	this->profile = userInfo->usri3_profile;


	this->homeDirDrive = userInfo->usri3_home_dir_drive;


	this->passwordExpired = userInfo->usri3_password_expired;
	return 0;
}
DWORD AccountInfoManager::Initialize() {
	PBYTE bytes = NULL;
	DWORD size = 0x1000;
	DWORD status = 0;
	DWORD entries;
	DWORD totalEntries;
	PUSER_INFO_3 info = NULL;
	status = NetUserEnum(NULL,
		3,
		FILTER_TEMP_DUPLICATE_ACCOUNT |
		FILTER_NORMAL_ACCOUNT |
		FILTER_INTERDOMAIN_TRUST_ACCOUNT |
		FILTER_WORKSTATION_TRUST_ACCOUNT |
		FILTER_SERVER_TRUST_ACCOUNT,
		&bytes,
		size,
		&entries,
		&totalEntries,
		NULL);

	if (status == ERROR_ACCESS_DENIED) {
		goto cleanup;
	}
	else if (status == ERROR_MORE_DATA) {
		do {
			size = size * 2;
		}while (ERROR_MORE_DATA == (status = NetUserEnum(NULL,
			3,
			FILTER_TEMP_DUPLICATE_ACCOUNT |
			FILTER_NORMAL_ACCOUNT |
			FILTER_INTERDOMAIN_TRUST_ACCOUNT |
			FILTER_WORKSTATION_TRUST_ACCOUNT |
			FILTER_SERVER_TRUST_ACCOUNT,
			&bytes,
			size,
			&entries,
			&totalEntries,
			NULL)));
	}
	
	for (int i = 0; i < entries; i++) {
		info = &((PUSER_INFO_3)bytes)[i];
		AccountInfo* user = new AccountInfo();
		user->Initialize(info);
		this->_users.push_back(user);
	}

cleanup:
	if (bytes != NULL)
		LocalFree(bytes);
	return status;
}

std::vector<AccountInfo*> AccountInfoManager::GetAccountList() {
	return this->_users;
}

AccountInfoManager::~AccountInfoManager() {
	for (auto user : this->_users) {
		if (user != NULL) {
			delete user;
		}
	}
}