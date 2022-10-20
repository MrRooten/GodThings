#include "utils.h"
#include "RegistryUtils.h"
#include <string>
#include <shlwapi.h>
#include "Service.h"
#include "StringUtils.h"
#include "Process.h"
#include "AccountInfo.h"
#include "Network.h"
#pragma comment(lib,"Shlwapi.lib")

DWORD EnumCallback(
	std::wstring key,
	PVOID pValue
	) {
	wprintf(L"%s %s\n", key.c_str(), (LPWSTR)pValue);
	return 0;
}
DWORD GetStartupPrograms() {
	GTPrintln(L"Get Startup Program");
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
			LOG_DEBUG_REASON("Error FindFirstFileW");
			break;
		}

		// List all the files in the directory with some info about them.

		do
		{
			if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				wprintf(L"\t%s   <DIR>\n", ffd.cFileName);
			}
			else
			{
				filesize.LowPart = ffd.nFileSizeLow;
				filesize.HighPart = ffd.nFileSizeHigh;
				wprintf(L"\t%s   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
			}
		} while (FindNextFileW(hFind, &ffd) != 0);
	} while (0);

	do {
		RegistryUtils utils(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
		auto a = utils.ListKeyValue();
		for (auto i : a) {
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
			}
			wprintf(L"\n");
		}
	} while (0);
	GTPrintln(L"");
	return 0;
}

DWORD GetServices() {
	ServiceManager svcMgr;
	svcMgr.SetAllServices();
	for (auto svcItem : svcMgr.services) {
		wprintf(L"%s %s\n", svcItem->GetServiceName().c_str(), svcItem->GetFilePath().c_str());
		GTPrintln(L"\tDescription:%s", svcItem->GetDescription().c_str());
		GTPrintln(L"\tFailure Action:%s", svcItem->GetFailureActionCommand());
		GTPrintln(L"\tState:%s", svcItem->GetServiceStatus().c_str());
	}
	GTPrintln(L"");
	return 0;
}



DWORD GetFilesRelateOpenCommands() {
	GTPrintln(L"Get File RelateOpen Command");
	RegistryUtils utils(L"HKEY_CLASSES_ROOT");
	auto subkeys = utils.ListSubKeys();
	for (auto subkey : subkeys) {
		if (StringUtils::HasEnding(subkey,L"file")) {
			std::wstring key = L"HKEY_CLASSES_ROOT\\" + subkey + L"\\shell\\open\\command";
			auto a = RegistryUtils::GetValueStatic(key.c_str(), L"");
			if (a.size() == 0) {
				continue;
			}
			GTPrintln(L"\t%s %s", subkey.c_str(),(LPWSTR)a.c_str());
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetUserInit() {
	GTPrintln(L"UserInit:");
	std::wstring key = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\";
	auto a = RegistryUtils::GetValueStatic(key.c_str(), L"Userinit");
	if (a.size() != 0) {
		GTPrintln(L"\t%s", (LPWSTR)a.c_str());
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetUserInitMprLogonScript() {
	GTPrintln(L"UserInitMprLogonScript:");
	std::wstring key = L"HKEY_CURRENT_USER\\Environment";
	auto a = RegistryUtils::GetValueStatic(key.c_str(), L"UserInitMprLogonScript");
	if (a.size() != 0) {
		GTPrintln(L"\t%s", (LPWSTR)a.c_str());
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetScreenSave() {
	GTPrintln(L"ScreenSave:");
	std::wstring key = L"HKEY_CURRENT_USER\\Control Panel\\Desktop";
	auto a = RegistryUtils::GetValueStatic(key.c_str(), L"SCRNSAVE.EXE");
	if (a.size() != 0) {
		GTPrintln(L"\t%s", (LPWSTR)a.c_str());
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetImageHijack() {
	GTPrintln(L"ImageHijack:");
	std::wstring key = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	RegistryUtils utils(key.c_str());
	auto subkeys = utils.ListSubKeys();
	for (auto subkey : subkeys) {
		std::wstring targetKey = key + subkey;
		auto a = RegistryUtils::GetValueStatic(targetKey.c_str(), L"debugger");
		if (a.size() != 0) {
			GTPrintln(L"\t%s %s", subkey.c_str(),(LPWSTR)a.c_str());
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetWaitforBackdoor() {
	GTPrintln(L"Waitfor:");
	ProcessManager proMgr;
	proMgr.UpdateInfo();
	for (auto item : proMgr.processesMap) {
		auto proName = item.second->processName;
		auto iproName = StringUtils::ToLower(proName);
		if (iproName.find(L"waitfor") != -1) {
			GTPrintln(L"\t%d %s", item.first, proName.c_str());
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetComHijack() {
	GTPrintln(L"Com Hijack:");
	std::wstring key = L"HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\";
	std::wstring inprocKey = L"InprocServer32";
	RegistryUtils utils(key);
	auto subkeys = utils.ListSubKeys();
	for (auto subkey : subkeys) {
		GTPrintln(L"%s\n", subkey.c_str());
		std::wstring targetKey = key + subkey + L"\\" + inprocKey;
		RegistryUtils utils(targetKey);
		auto items = utils.ListKeyValue();
		if (items.size() == 0) {
			continue;
		}
		for (auto item : items) {
			GTPrintln(L"%s %s", item.first.c_str(), item.second.c_str());
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetAppInit_Dlls() {
	GTPrintln(L"AppInit_Dlls Hijack:");
	std::wstring key = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	auto buffer = RegistryUtils::GetValueStatic(key.c_str(), L"AppInit_DLLs");
	if (buffer.size() == 0) {
		return 0;
	}

	auto buffer2 = RegistryUtils::GetValueStatic(key.c_str(), L"LoadAppInit_DLLs");
	GTPrintln(L"\tAppInit_DLLs Path: %s \n\tEnable AppInit_DLLs: %d", (LPWSTR)buffer.c_str(),buffer2.c_str()[0]);
	GTPrintln(L"");
	return 0;
}

DWORD GetMSDTCBackdoor() {
	GTPrintln(L"MSDTC Backddor:");
	std::wstring key = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI";
	RegistryUtils utils(key);
	auto items = utils.ListKeyValue();
	for (auto item : items) {
		GTPrintln(L"\t%s %s", item.first.c_str(), item.second.c_str());
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetShadowAccount() {
	GTPrintln(L"Shadow Account Backddor:");
	AccountInfoManager mgr;
	mgr.Initialize();
	auto users = mgr.GetAccountList();
	for (auto user : users) {
		if (StringUtils::HasEnding(user->userName, L"$")) {
			GTPrintln(L"\t%s", user->userName.c_str());
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetRundll32Backdoor() {
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
		}
	}
	GTPrintln(L"");
	return 0;
}

DWORD GetProcesses() {
	GTPrintln(L"Process List:");
	ProcessManager mgr;
	mgr.UpdateInfo();
	for (auto item : mgr.processesMap) {
		Process* process = item.second;
		GTPrintln(L"%.4d %s %s %s %d", process->GetPID(), 
			process->processName.c_str(), 
			process->GetUserName().c_str(),
			process->GetImageState()->cmdline.c_str(),process->GetImageState()->cmdline.size());
	}
	return 0;
}




DWORD GetTCPConnection() {
	NetworkManager mgr;
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
	}
	return 0;
}