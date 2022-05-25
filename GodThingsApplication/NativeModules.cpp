#include "NativeModules.h"
#include "Process.h"
#include "StringUtils.h"
#include "Service.h"
#include "RegistryUtils.h"
#include "shlwapi.h"
#include "Network.h"
ProcessModule::ProcessModule() {
	this->Name = L"Process";
	this->Path = L"Process";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Process Infomation";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ProcessModule::ModuleRun() {
	ResultSet* result = new ResultSet();

	ProcessManager* mgr = new ProcessManager();
	mgr->SetAllProcesses();
	for (auto item : mgr->processesMap) {
		//result->dataDict["id"].push_back(std::to_string(item.first));
		result->PushDictOrdered("id", std::to_string(item.first));
		//result->dataDict["name"].push_back(StringUtils::ws2s(item.second->processName));
		result->PushDictOrdered("name", StringUtils::ws2s(item.second->processName));
		item.second->SetProcessUserName();
		result->PushDictOrdered("userName", StringUtils::ws2s(item.second->userName));
		item.second->SetProcessImageState();
		result->PushDictOrdered("cmdline", StringUtils::ws2s(item.second->imageState->cmdline));
		result->PushDictOrdered("filepath", StringUtils::ws2s(item.second->imageState->imageFileName));
	}
	delete mgr;
	result->SetType(DICT);
	return result;
}

ListTestModule::ListTestModule() {
	this->Name = L"ListTest";
	this->Path = L"ListTest";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Test List";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ListTestModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	result->dataArray = { "abc","def","ghi" };
	result->SetType(ARRAY);
	return result;
}

ServiceModule::ServiceModule() {
	this->Name = L"Service";
	this->Path = L"Service";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Service Info";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ServiceModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	ServiceManager* mgr = new ServiceManager();
	mgr->SetAllServices();
	for (auto item : mgr->services) {
		//result->dataDict["serviceName"].push_back(StringUtils::ws2s(item->serviceName));
		result->PushDictOrdered("serviceName", StringUtils::ws2s(item->serviceName));
		//result->dataDict["serviceStatus"].push_back(StringUtils::ws2s(item->GetServiceStatus()));
		result->PushDictOrdered("serviceStatus", StringUtils::ws2s(item->GetServiceStatus()));
		item->SetDescription();
		std::wstring a = L"";
		if (lstrlenW(item->pDescription->lpDescription)==0) {
			a = L"";
		}
		else {
			a = item->pDescription->lpDescription;
		}
		//result->dataDict["description"].push_back(StringUtils::ws2s(a));
		result->PushDictOrdered("description", StringUtils::ws2s(a));
	}
	delete mgr;
	result->SetType(DICT);
	return result;
}

StartupModule::StartupModule() {
	this->Name = L"Startup";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Startup Programs";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* StartupModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	do {
		HANDLE hFind = INVALID_HANDLE_VALUE;
		WCHAR appdataPath[101];
		LARGE_INTEGER filesize;
		GetEnvironmentVariableW(L"appdata", appdataPath, 99);
		if (lstrlenW(appdataPath) == 0) {
			break;
		}
		std::wstring path;
		path = appdataPath + std::wstring(L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\");

		if (PathFileExistsW(path.c_str()) == FALSE) {
			wprintf(L"The Startup in menu is not exist");
			break;
		}
		path = path + L"*";
		WIN32_FIND_DATAW ffd;
		hFind = FindFirstFileW(path.c_str(), &ffd);

		if (INVALID_HANDLE_VALUE == hFind) {
			Logln(DEBUG_LEVEL, L"[%s:%s:%d]:%d,%s", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			break;
		}

		// List all the files in the directory with some info about them.

		do
		{
			if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				//wprintf(L"\t%s   <DIR>\n", ffd.cFileName);
			}
			else
			{
				filesize.LowPart = ffd.nFileSizeLow;
				filesize.HighPart = ffd.nFileSizeHigh;
				//wprintf(L"\t%s   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
				//result->dataDict["fileName"].push_back(StringUtils::ws2s(ffd.cFileName));
				result->PushDictOrdered("fileName", StringUtils::ws2s(ffd.cFileName));
				//result->dataDict["source"].push_back(StringUtils::ws2s(path));
				result->PushDictOrdered("source", StringUtils::ws2s(path));
				//result->dataDict["cmdline"].push_back(StringUtils::ws2s(ffd.cFileName));
				result->PushDictOrdered("cmdline", StringUtils::ws2s(ffd.cFileName));
			}
		} while (FindNextFileW(hFind, &ffd) != 0);
	} while (0);

	do {
		RegistryUtils utils(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
		auto a = utils.ListKeyValue();
		for (auto i : a) {
			result->PushDictOrdered("fileName",StringUtils::ws2s(i.first));
			result->PushDictOrdered("cmdline",StringUtils::ws2s(i.second));
			result->PushDictOrdered("source","HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
			GTPrintln(L"\t%s %s", i.first.c_str(), (LPWSTR)i.second.c_str());
		}
	} while (0);

	std::vector<LPWSTR> startupKeys = {
		(LPWSTR)L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		(LPWSTR)L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		(LPWSTR)L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		(LPWSTR)L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		(LPWSTR)L"HKEY_CURRENT_USER\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Run",
		(LPWSTR)L"HKEY_CURRENT_USER\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\RunOnce"
	};
	do {
		for (LPWSTR key : startupKeys) {
			RegistryUtils utils(key);
			auto items = utils.ListKeyValue();
			GTPrintln(L"%s", key);
			for (auto item : items) {
				GTPrintln(L"\t%s %s", item.first.c_str(), item.second.c_str());
				result->PushDictOrdered("fileName",StringUtils::ws2s(item.first));
				result->PushDictOrdered("cmdline",StringUtils::ws2s(item.second));
				result->PushDictOrdered("source",StringUtils::ws2s(key));
			}
			wprintf(L"\n");
		}
	} while (0);
	result->SetType(DICT);
	return result;
}

FilesRelateOpenCommandsModule::FilesRelateOpenCommandsModule() {
	this->Name = L"FilesRelate";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get files relate open programs";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* FilesRelateOpenCommandsModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	RegistryUtils utils(L"HKEY_CLASSES_ROOT");
	auto subkeys = utils.ListSubKeys();
	for (auto subkey : subkeys) {
		if (StringUtils::HasEnding(subkey, L"file")) {
			std::wstring key = L"HKEY_CLASSES_ROOT\\" + subkey + L"\\shell\\open\\command";
			auto a = RegistryUtils::GetValueStatic(key.c_str(), L"");
			if (a.size() == 0) {
				continue;
			}
			GTPrintln(L"\t%s %s", subkey.c_str(), (LPWSTR)a.c_str());
			result->PushDictOrdered("file",StringUtils::ws2s(subkey));
			result->PushDictOrdered("program",StringUtils::ws2s((LPWSTR)a.c_str()));
		}
	}
	result->SetType(DICT);
	return result;
}

NetworkModule::NetworkModule() {
	this->Name = L"NetworkConnection";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Network Connection";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* NetworkModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	TCPManager mgr;
	mgr.SetTCPConnection();
	ProcessManager proMgr;
	proMgr.UpdateInfo();
	for (auto connection : mgr.connections) {
		wprintf(L"%s:%d -> %s:%d %s:%d:%s\n",
			connection->GetLocalIPAsString().c_str(),
			connection->localPort,
			connection->GetRemoteIPAsString().c_str(),
			connection->remotePort,
			connection->GetStateAsString().c_str(),
			connection->owningPid,
			proMgr.processesMap[connection->owningPid]->processName.c_str()
		);
		result->PushDictOrdered("localIP", StringUtils::ws2s(connection->GetLocalIPAsString().c_str()));
		result->PushDictOrdered("localPort", std::to_string(connection->localPort));
		result->PushDictOrdered("remoteIP", StringUtils::ws2s(connection->GetRemoteIPAsString().c_str()));
		result->PushDictOrdered("remotePort", std::to_string(connection->remotePort));
		result->PushDictOrdered("state", StringUtils::ws2s(connection->GetStateAsString().c_str()));
		result->PushDictOrdered("pid", std::to_string(connection->owningPid));
	}
	result->SetType(DICT);
	return result;
}

Rundll32Backdoor::Rundll32Backdoor() {
	this->Name = L"Rundll32Backdoor";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Rundll32 Backdoor";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* Rundll32Backdoor::ModuleRun() {
	ResultSet* result = new ResultSet();
	GTPrintln(L"Rundll32 Backdoor:");
	ProcessManager mgr;
	mgr.UpdateInfo();
	for (auto item : mgr.processesMap) {
		auto proName = item.second->processName;
		auto iproName = StringUtils::ToLower(proName);
		if (iproName.find(L"rundll") != -1) {
			Process* process = item.second;
			auto imageState = process->GetImageState();
			std::wstring cmdline = imageState->cmdline;
			printf("\t%d %s", item.first, StringUtils::ws2s(cmdline).c_str());
			result->PushDictOrdered("pid",std::to_string(item.first));
			result->PushDictOrdered("cmdline", StringUtils::ws2s(cmdline).c_str());
			result->report = "Might have rundll32 backdoor";
		}
	}
	result->SetType(DICT);
	return result;
}

ShadowAccount::ShadowAccount() {
	this->Name = L"ShadowAccount";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Shadow Account";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
#include "AccountInfo.h"
ResultSet* ShadowAccount::ModuleRun() {
	ResultSet* result = new ResultSet();
	GTPrintln(L"Shadow Account Backddor:");
	AccountInfoManager mgr;
	mgr.Initialize();
	auto users = mgr.GetAccountList();
	for (auto user : users) {
		if (StringUtils::HasEnding(user->userName, L"$")) {
			//GTPrintln(L"\t%s", user->userName.c_str());
			result->PushDictOrdered("username", StringUtils::ws2s(user->userName));
			result->report = "Might have shadow manager";
		}
	}
	result->SetType(DICT);
	return result;
}

UnsignedRunningProcess::UnsignedRunningProcess() {
	this->Name = L"UnsignedRunningProcess";
	this->Path = this->Name;
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get programs that unsigned in processes";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* UnsignedRunningProcess::ModuleRun(){
	ResultSet* result = new ResultSet();
	GTPrintln(L"Rundll32 Backdoor:");
	ProcessManager mgr;
	mgr.UpdateInfo();
	for (auto item : mgr.processesMap) {
		auto proName = item.second->processName;
		auto iproName = StringUtils::ToLower(proName);
		if (item.second->imageState->IsSigned() == false) {
			Process* process = item.second;
			auto imageState = process->GetImageState();
			std::wstring cmdline = imageState->cmdline;
			printf("\t%d %s", item.first, StringUtils::ws2s(cmdline).c_str());
			result->PushDictOrdered("pid", std::to_string(item.first));
			result->PushDictOrdered("cmdline", StringUtils::ws2s(cmdline).c_str());
			result->PushDictOrdered("info", StringUtils::ws2s(item.second->imageState->GetSignInfo()).c_str());
			result->report = "There is unsigned process running";
		}
	}
	result->SetType(DICT);
	return result;
}
