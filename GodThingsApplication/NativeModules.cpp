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
		result->PushDictOrdered("name", StringUtils::ws2s(item.second->GetProcessName()));

		result->PushDictOrdered("userName", StringUtils::ws2s(item.second->GetUserName()));
		result->PushDictOrdered("cmdline", StringUtils::ws2s(item.second->GetImageState()->cmdline));
		result->PushDictOrdered("filepath", StringUtils::ws2s(item.second->GetImageState()->imageFileName));
	}
	delete mgr;
	result->SetType(DICT);
	return result;
}

ListTestModule::ListTestModule() {
	this->Name = L"ListTest";
	this->Path = L"Test";
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
	this->Name = L"Services";
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
	this->Path = L"Other";
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
			LOG_DEBUG(L"Can not find first file");
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
			for (auto item : items) {
				result->PushDictOrdered("fileName",StringUtils::ws2s(item.first));
				result->PushDictOrdered("cmdline",StringUtils::ws2s(item.second));
				result->PushDictOrdered("source",StringUtils::ws2s(key));
			}
		}
	} while (0);
	result->SetType(DICT);
	return result;
}

FilesRelateOpenCommandsModule::FilesRelateOpenCommandsModule() {
	this->Name = L"FilesRelate";
	this->Path = L"Registry";
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
			result->PushDictOrdered("file",StringUtils::ws2s(subkey));
			result->PushDictOrdered("program",StringUtils::ws2s((LPWSTR)a.c_str()));
		}
	}
	result->SetType(DICT);
	return result;
}

NetworkModule::NetworkModule() {
	this->Name = L"NetworkConnection";
	this->Path = L"Network";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Network Connection";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* NetworkModule::ModuleRun() {
	ResultSet* result = new ResultSet();
	NetworkManager mgr;
	mgr.SetTCPConnection();
	ProcessManager proMgr;
	proMgr.UpdateInfo();
	for (auto connection : mgr.connections) {
		result->PushDictOrdered("local ip", StringUtils::ws2s(connection->GetLocalIPAsString().c_str()));
		result->PushDictOrdered("local port", std::to_string(connection->localPort));
		result->PushDictOrdered("remote ip", StringUtils::ws2s(connection->GetRemoteIPAsString().c_str()));
		result->PushDictOrdered("remote port", std::to_string(connection->remotePort));
		result->PushDictOrdered("state", StringUtils::ws2s(connection->GetStateAsString().c_str()));
		result->PushDictOrdered("pid", std::to_string(connection->owningPid));
		result->PushDictOrdered("process name", StringUtils::ws2s(Process(connection->owningPid).GetProcessName()));
	}
	result->SetType(DICT);
	return result;
}

Rundll32Backdoor::Rundll32Backdoor() {
	this->Name = L"Rundll32Backdoor";
	this->Path = L"Process";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Rundll32 Backdoor";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* Rundll32Backdoor::ModuleRun() {
	ResultSet* result = new ResultSet();
	ProcessManager mgr;
	mgr.UpdateInfo();
	for (auto item : mgr.processesMap) {
		auto proName = item.second->processName;
		auto iproName = StringUtils::ToLower(proName);
		if (iproName.find(L"rundll") != -1) {
			Process* process = item.second;
			auto imageState = process->GetImageState();
			std::wstring cmdline = imageState->cmdline;
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
	this->Path = L"Account";
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
	this->Path = L"Process";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get programs that unsigned in processes";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* UnsignedRunningProcess::ModuleRun(){
	ResultSet* result = new ResultSet();
	ProcessManager mgr;
	mgr.UpdateInfo();
	for (auto item : mgr.processesMap) {
		auto proName = item.second->processName;
		auto iproName = StringUtils::ToLower(proName);
		if (item.second->GetImageState()->IsSigned() == false) {
			Process* process = item.second;
			auto imageState = process->GetImageState();
			std::wstring cmdline = imageState->cmdline;
			result->PushDictOrdered("pid", std::to_string(item.first));
			result->PushDictOrdered("cmdline", StringUtils::ws2s(cmdline).c_str());
			result->PushDictOrdered("info", StringUtils::ws2s(item.second->GetImageState()->GetSignInfo()).c_str());
			result->report = "There is unsigned process running";
		}
	}
	result->SetType(DICT);
	return result;
}

USBHistory::USBHistory() {
	this->Name = L"USBHistory";
	this->Path = L"Registry";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get USB History";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* USBHistory::ModuleRun() {
	ResultSet* result = new ResultSet();
	std::wstring key = L"HKEY_LOCAL_MACHINE\\SYSTEM\\";
	std::wstring timeKey = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\";
	RegistryUtils utils(timeKey.c_str());
	auto subkeys = utils.ListSubKeysChain();
	for (auto& subkey : subkeys) {
		auto time = subkey.GetLastWriteTime();
		wprintf(L"%s %s\n", subkey.GetKeyName().c_str(), GTTime(time).ToString().c_str());
		result->PushDictOrdered("Device Name", StringUtils::ws2s(subkey.GetKeyName()));
		result->PushDictOrdered("Time", StringUtils::ws2s(GTTime(time).ToString()));
	}
	result->SetType(DICT);
	return result;
}

PrefetchModule::PrefetchModule() {
	this->Name = L"Prefetch";
	this->Path = L"File";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Prefetch files";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* PrefetchModule::ModuleRun() {
	return nullptr;
}

ListSchduleTask::ListSchduleTask() {
	this->Name = L"ListSchduleTask";
	this->Path = L"Other";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Prefetch files";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
#include "OtherInfo.h"
ResultSet* ListSchduleTask::ModuleRun() {
	ResultSet* result = new ResultSet();
	SchduleTaskMgr* mgr = SchduleTaskMgr::GetMgr();
	auto tasks = mgr->GetTasks();
	for (auto& task : tasks) {
		result->PushDictOrdered("Name", StringUtils::ws2s(task.getName()));
	}
	result->SetType(DICT);
	return result;
}

#include <thread>
#include <chrono>
LoopNetstat::LoopNetstat() {
	this->Name = L"LookNetstat";
	this->Path = L"Network";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Read Network stat in seconds";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
BOOL WINAPI consoleHandler(DWORD signal) {
	if (signal == CTRL_C_EVENT) {
		exit(0);
	}

	return TRUE;
}

std::vector<Connection> _what_is_second_doesnot_have(std::vector<Connection*> first, std::vector<Connection*> second) {
	std::vector<Connection> res;
	
	return res;
}

ResultSet* LoopNetstat::ModuleRun() {
	bool running = TRUE;
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		return nullptr;
	}
	NetworkManager mgr;
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	std::vector<Connection*> last;
	for (int i = 0; i < 1000000;i++) {
		auto conns = mgr.GetAllConnections();
		auto changes = _what_is_second_doesnot_have(conns, last);
		//print changes

	}
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << "[s]" << std::endl;
	std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << "[ns]" << std::endl;
	return nullptr;
}

MailiousProcessDlls::MailiousProcessDlls() {
	this->Name = L"UnsignedProcessDlls";
	this->Path = L"Process";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"List a Dlls of Process that not signed by trust provider";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* MailiousProcessDlls::ModuleRun() {
	ResultSet* result = new ResultSet();
	if (!this->args.contains("pid")) {
		result->SetErrorMessage("Must set a pid to get dll information");
		return result;
	}
	GTTime* t = NULL;
	if (this->args.contains("date")) {
		t = new GTTime(this->args["date"].c_str());
	}
	auto pid = stoi(this->args["pid"]);
	Process* p = new Process(pid);
	if (p == NULL) {
		result->SetErrorMessage("Error: " + StringUtils::ws2s(GetLastErrorAsString()));
		return result;
	}
	auto dlls = p->GetLoadedDlls();
	for (auto& dll : dlls) {
		auto path = dll.GetPath();
		auto sign = VerifyEmbeddedSignature(path.c_str());
		FileInfo dllInfo(path.c_str());
		if (!sign->IsSignature()) {
			result->PushDictOrdered("Path", StringUtils::ws2s(path));
			result->PushDictOrdered("Reason", "No signature");
		}
		delete sign;
	}
	result->SetType(DICT);
	return result;
}
