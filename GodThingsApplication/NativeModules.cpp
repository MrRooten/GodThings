#include "NativeModules.h"
#include "Process.h"
#include "StringUtils.h"
#include "Service.h"
#include "RegistryUtils.h"
#include "shlwapi.h"
#include <tinyxml2.h>
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

		result->PushDictOrdered("userName", StringUtils::ws2s(item.second->UserName()));
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
		result->PushDictOrdered("serviceName", StringUtils::ws2s(item->GetServiceName()));
		//result->dataDict["serviceStatus"].push_back(StringUtils::ws2s(item->GetServiceStatus()));
		result->PushDictOrdered("serviceStatus", StringUtils::ws2s(item->GetServiceStatus()));
		auto a = item->GetDescription();
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
		path = std::wstring(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

		if (PathFileExistsW(path.c_str()) == FALSE) {
			//wprintf(L"The Startup in menu is not exist");
			break;
		}
		path = path + L"*";
		WIN32_FIND_DATAW ffd;
		hFind = FindFirstFileW(path.c_str(), &ffd);

		if (INVALID_HANDLE_VALUE == hFind) {
			LOG_DEBUG_REASON(L"Can not find first file");
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
			//wprintf(L"The Startup in menu is not exist");
			break;
		}
		path = path + L"*";
		WIN32_FIND_DATAW ffd;
		hFind = FindFirstFileW(path.c_str(), &ffd);

		if (INVALID_HANDLE_VALUE == hFind) {
			LOG_DEBUG_REASON(L"Can not find first file");
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
		result->PushDictOrdered("process name", StringUtils::ws2s(proMgr.processesMap[connection->owningPid]->GetProcessName()));
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
			result->report = "Might have shadow account";
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
		//wprintf(L"%s %s\n", subkey.GetKeyName().c_str(), GTTime(time).ToString().c_str());
		result->PushDictOrdered("Device Name", StringUtils::ws2s(subkey.GetKeyName()));
		result->PushDictOrdered("Time", StringUtils::ws2s(GTTime(time).String()));
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
		result->PushDictOrdered("Path", StringUtils::ws2s(task.getPath()));
		result->PushDictOrdered("State", StringUtils::ws2s(task.GetState()));
	}
	result->SetType(DICT);
	return result;
}

#include <thread>
#include <chrono>
WatchNetstat::WatchNetstat() {
	this->Name = L"WatchNetstat";
	this->Path = L"Network";
	this->Type = L"LastMode";
	this->Class = L"GetInfo";
	this->Description = L"Read Network stat in seconds";
	this->RunType = ModuleNotAuto;
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
BOOL WINAPI consoleHandler(DWORD signal) {
	if (signal == CTRL_C_EVENT) {
		exit(0);
	}

	return TRUE;
}

std::vector<std::pair<bool, Connection>> _what_is_second_doesnot_have(std::vector<Connection>& first, std::vector<Connection>& second) {
	std::vector<std::pair<bool,Connection>> res;
	bool flag = false;
	for (auto s : second) {
		flag = false;
		for (auto f : first) {
			if (f == s) {
				flag = true;
				break;
			}
			
		}

		if (flag == false) {
			res.push_back(std::pair(true, s));
		}
	}

	for (auto f : first) {
		flag = false;
		for (auto s : second) {
			if (f == s) {
				flag = true;
				break;
			}

		}

		if (flag == false) {
			res.push_back(std::pair(false, f));
		}
	}

	return res;
}

std::vector<Connection> _copy(std::vector<Connection*> vs) {
	std::vector<Connection> res;
	for (auto s : vs) {
		Connection c = *s;
		res.push_back(c);
	}

	return res;
}

ResultSet* WatchNetstat::ModuleRun() {
	bool running = TRUE;
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		return nullptr;
	}
	ProcessManager proMgr;
	proMgr.UpdateInfo();
	NetworkManager mgr;
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	std::vector<Connection> last = _copy(mgr.GetAllConnections());
	for (auto& change : last) {
		
		wprintf(L"[Base] %s %d %s %d [%d] %s\n", change.GetLocalIPAsString().c_str(),
				change.localPort,
				change.GetRemoteIPAsString().c_str(), change.remotePort,
			change.owningPid, proMgr.processesMap[change.owningPid]->GetProcessName().c_str());
	}
	std::vector<Connection> conns;
	int i = 0;
	for (; ;i++) {
		proMgr.UpdateInfo();
		conns = _copy(mgr.GetAllConnections());
		auto changes = _what_is_second_doesnot_have(conns, last);
		//print changes
		for (auto& change : changes) {
			GTWString protocol = L"";
			if (change.second.protocol == Protocol::UDP) {
				protocol = L"UDP";
			}
			else {
				protocol = L"TCP";
			}

			if (change.first == false) {
				if (proMgr.processesMap[change.second.owningPid] != NULL) {
					wprintf(L"[-]%s %s %d %s %d %s [%d] %s\n", 
						protocol.c_str(),
						change.second.GetLocalIPAsString().c_str(),
						change.second.localPort,
						change.second.GetRemoteIPAsString().c_str(), change.second.remotePort,
						change.second.GetStateAsString().c_str(),
						change.second.owningPid, 
						proMgr.processesMap[change.second.owningPid]->GetProcessName().c_str());
				}
				else {
					wprintf(L"[-]%s %s %d %s %d %s [%d] %s\n",
						protocol.c_str(),
						change.second.GetLocalIPAsString().c_str(),
						change.second.localPort,
						change.second.GetRemoteIPAsString().c_str(), change.second.remotePort,
						change.second.GetStateAsString().c_str(),
						change.second.owningPid,
						L"");
				}
			}
			else {
				if (proMgr.processesMap[change.second.owningPid] != NULL) {
					wprintf(L"[+]%s %s %d %s %d %s [%d] %s\n",
						protocol.c_str(),
						change.second.GetLocalIPAsString().c_str(),
						change.second.localPort,
						change.second.GetRemoteIPAsString().c_str(), change.second.remotePort,
						change.second.GetStateAsString().c_str(),
						change.second.owningPid,
						proMgr.processesMap[change.second.owningPid]->GetProcessName().c_str());
				}
				else {
					wprintf(L"[+]%s %s %d %s %d %s [%d] %s\n",
						protocol.c_str(),
						change.second.GetLocalIPAsString().c_str(),
						change.second.localPort,
						change.second.GetRemoteIPAsString().c_str(), change.second.remotePort,
						change.second.GetStateAsString().c_str(),
						change.second.owningPid,
						L"");
				}
			}
		}
		last = conns;
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
	this->RunType = ModuleNeedArgs;
	this->Description = L"List a Dlls of Process that not signed by trust provider";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* MailiousProcessDlls::ModuleRun() {
	ResultSet* result = new ResultSet();
	std::vector<UINT32> pids;
	if (!this->args.contains("pid")) {
		result->SetErrorMessage("Must set a pid to get dll information: ./GodAgent.exe Process.UnsignedProcessDlls 'pid=${pid}',running all processes");
		LOG_INFO(L"Must set a pid to get dll information: ./GodAgent.exe Process.UnsignedProcessDlls 'pid=${pid}',running all processes");
		this->args["pid"] = "*";
	}

	if (this->args["pid"] == "*") {
		auto mgr = ProcessManager::GetMgr();
		mgr->SetAllProcesses();
		for (auto pid : mgr->processesMap) {
			pids.push_back(pid.first);
		}
	}
	else {
		auto pid = stoi(this->args["pid"]);
		pids.push_back(pid);
	}
	for (auto pid : pids) {
		SetLastError(0);
		GTTime* t = NULL;
		if (this->args.contains("date")) {
			t = new GTTime(this->args["date"].c_str());
		}
		Process* p = NULL;
		p = new Process(pid);
		wprintf(L"Running Process %d %s\n", p->GetPID(), p->GetProcessName().c_str());
		if (p == NULL) {
			result->SetErrorMessage("Error: " + StringUtils::ws2s(GetLastErrorAsString()));
			return result;
		}
		auto dlls = p->GetLoadedDlls();
		if (dlls.size() == 0) {
			continue;
		}
		for (auto& dll : dlls) {
			auto path = dll.GetPath();
			auto sign = VerifyEmbeddedSignature(path.c_str());
			FileInfo dllInfo(path.c_str());
			if (!sign->IsSignature()) {
				result->PushDictOrdered("Pid", to_string(pid));
				result->PushDictOrdered("Path", StringUtils::ws2s(path));
				result->PushDictOrdered("Reason", "No signature");
				wprintf(L"\tUnsigned dlls %d %s\n", pid, path.c_str());
			}
			delete sign;
		}
		if (p != NULL) {
			delete p;
		}
	}
	ProcessManager::GetMgr()->~ProcessManager();
	result->SetType(DICT);
	return result;
}

MailiousCodeInjection::MailiousCodeInjection() {
	this->Name = L"MailiousCodeInjection";
	this->Path = L"Process";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Detect is there are mailious shellcode";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* MailiousCodeInjection::ModuleRun() {
	return nullptr;
}

ValidSvcHost::ValidSvcHost() {
	this->Name = L"ValidSvcHost";
	this->Path = L"Service";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Detect if there are svchost that suspicious";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ValidSvcHost::ModuleRun() {
	return nullptr;
}

RecentRunning::RecentRunning() {
	this->Name = L"RecentRunning";
	this->Path = L"System";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get System recent running process";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

std::wstring ROT13(std::wstring source) {
	std::wstring transformed;
	for (size_t i = 0; i < source.size(); ++i) {
		if ((source[i] >= L'a' && source[i] <= L'z') || (source[i] >= L'A' && source[i] <= L'Z')) {
			if (source[i] >= L'a' && source[i] <= L'z') {
				transformed.append(1, (((source[i] - L'a') + 13) % 26) + L'a');
			} else 
			if (source[i] >= L'A' && source[i] <= L'Z') {
				transformed.append(1, (((source[i] - L'A') + 13) % 26) + L'A');
			}
		}
		else {
			transformed.append(1, source[i]);
		}
	}
	return transformed;
}
#include "PrivilegeUtils.h"
#include "EvtInfo.h"
class ShellCore9707 {
public:
	GTString createTime;
	GTString commandLine;
	ShellCore9707(const wchar_t* xml);
};

ShellCore9707::ShellCore9707(const wchar_t* xml) {
	tinyxml2::XMLDocument doc;
	doc.Parse(StringUtils::ws2s(xml).c_str());
	auto root_element = doc.RootElement();
	auto system_element = root_element->FirstChildElement();
	auto next = system_element->FirstChildElement();
	auto user_element = system_element->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;
	while (next) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->createTime = attr->Value();
			}
		}
		next = next->NextSiblingElement();
	}
	next = user_element->FirstChildElement();
	while (next != NULL) {
		value = (char*)next->GetText();
		name = (char*)next->Value();
		auto attr = next->FindAttribute("Name");
		if (attr != NULL && _strcmpi(attr->Value(), "Command") == 0) {
			this->commandLine = value;
		}

		next = next->NextSiblingElement();
	}
}

DWORD RecentRunningEventLog(Evt* evt, PVOID data) {
	auto evtXml = evt->GetXml();
	auto result = (std::vector<ShellCore9707*>*)data;
	auto xml = StringUtils::ws2s(evt->GetXml().c_str());
	tinyxml2::XMLDocument doc;
	auto error = doc.Parse(xml.c_str());
	auto root = doc.RootElement();
	auto system = root->FirstChildElement();
	tinyxml2::XMLElement* child_system_next = system->FirstChildElement();
	tinyxml2::XMLElement* userdata_next = system->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;

	while (child_system_next) {
		value = (char*)child_system_next->GetText();
		name = (char*)child_system_next->Value();
		if (_strcmpi(name, "EventId") == 0) {
			auto event_id = stoi(value);
			if (event_id == 9707) {
				result->push_back(new ShellCore9707(evtXml.c_str()));
				break;
			}
		}
		child_system_next = child_system_next->NextSiblingElement();
	}
	return 0;
}

ResultSet* RecentRunning::ModuleRun() {
	ResultSet* result = new ResultSet();
	std::wstring alluserAssist = L"HKEY_USERS";
	RegistryUtils allUserAssistReg(alluserAssist);
	auto users = allUserAssistReg.ListSubKeys();
	for (auto& user : users) {
		if (user == L".DEFAULT") {
			continue;
		}

		//wprintf(L"%s %s\n", user.c_str(),ConvertSidToUsername(user.c_str()));
		std::wstring userAssist = L"HKEY_USERS\\" + user + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
		RegistryUtils userAssistReg(userAssist);
		auto subs = userAssistReg.ListSubKeys();
		std::map<std::wstring, UserAssistParser> assistMap;
		for (auto& sub : subs) {
			std::wstring key = userAssist + L"\\" + sub + L"\\count";
			RegistryUtils utils(key);
			auto names = utils.ListValueNames();
			for (auto& _name : names) {
				auto name = ROT13(_name);
				auto buffer = RegistryUtils::GetValueStatic(key.c_str(), _name.c_str());
				UserAssistParser parser(buffer);
				assistMap[name] = parser;
				result->PushDictOrdered("name", StringUtils::ws2s(name));
				result->PushDictOrdered("exec", StringUtils::ws2s(parser.GetLastRun()));
			}
		}
	}

	Dir d(L"C:\\Windows\\Prefetch");

	auto files = d.listFiles();
	std::vector<std::wstring> pfs;
	for (auto& f : files) {
		if (f.ends_with(L".pf")) {
			pfs.push_back(f);
		}
	}
	files.clear();
	for (auto& pf : pfs) {
		auto s = L"C:\\Windows\\Prefetch\\" + pf;
		PrefetchFile* f = new PrefetchFile(s);
		f->Parse();
		//wprintf(L"%s\n", pf.c_str());
		auto times = f->GetExecTime();
		for (auto& time : times) {
			if (time.year < 1970) {
				continue;
			}
			//wprintf(L"\t%s\n", time.ToString().c_str());
			result->PushDictOrdered("name", StringUtils::ws2s(pf));
			result->PushDictOrdered("exec", StringUtils::ws2s(time.String()));
		}
		delete f;
	}
	EvtInfo info;
	EvtFilter filter;
	filter.ids = L"9707";
	filter.logName = L"Microsoft-Windows-Shell-Core/Operational";
	std::vector<ShellCore9707*> events;
	if (this->args.contains("path")) {
		info.EnumEventLogs(filter, RecentRunningEventLog, &events, false, (wchar_t*)StringUtils::s2ws(this->args["path"]).c_str());
	}
	else {
		info.EnumEventLogs(filter, RecentRunningEventLog, &events, false, NULL);
	}
	for (auto& e : events) {
		result->PushDictOrdered("name", e->commandLine);
		auto t = GTTime::FromISO8601(StringUtils::s2ws(e->createTime));
		result->PushDictOrdered("exec", StringUtils::ws2s(t.String()));
	}
	
	result->SetType(DICT);
	return result;
}

MRUList::MRUList() {
	this->Name = L"MRUList";
	this->Path = L"Registry";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Most Recent user list";
	this->RunType = ModuleNotImplement;
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* MRUList::ModuleRun() {
	return nullptr;
}

Accounts::Accounts() {
	this->Name = L"Accounts";
	this->Path = L"Registry";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Get Accounts";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* Accounts::ModuleRun() {
	ResultSet* result = new ResultSet();
	AccountInfoManager mgr;
	mgr.Initialize();
	auto users = mgr.GetAccountList();
	for (auto user : users) {
		result->PushDictOrdered("Uid", std::to_string(user->userId));
		result->PushDictOrdered("Username", StringUtils::ws2s(user->userName));
		result->PushDictOrdered("LastLogon", StringUtils::ws2s(user->GetLastLogon().String()));
		result->PushDictOrdered("LastLogoff", StringUtils::ws2s(user->GetLastLogoff().String()));
		result->PushDictOrdered("Comment", StringUtils::ws2s(user->GetComment()));
		
	}
	result->SetType(DICT);
	return result;
}

RecentApps::RecentApps() {
	this->Name = L"RecentApps";
	this->Path = L"Registry";
	this->Type = L"Native";
	this->Class = L"GetInfo";
	this->Description = L"Recent Apps";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* RecentApps::ModuleRun() {
	
	auto s = L"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps";
	RegistryUtils utils(s);
	auto keys = utils.ListSubKeys();
	for (auto& key : keys) {
		std::wstring target = s + std::wstring(L"\\") + key;
		RegistryUtils key(target.c_str());
		auto ks = key.ListValueNames();
		for (auto& k : ks) {
			auto value = RegistryUtils::GetValueStatic(target.c_str(), k.c_str());
		}
	}
	return nullptr;
}


