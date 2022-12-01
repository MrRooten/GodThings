#pragma once
#include <string>
#include <set>
#include "PythonUtils.h"
#include "FileInfo.h"
#include "utils.h"
#include "OtherInfo.h"
#include "EvtInfo.h"
#include "Process.h"
#include "Service.h"
#include "ProcServer.h"
#include "Module.h"
class ArgsHelper {
public:
	static void help(wchar_t *file) {
		std::wstring f(file);

		wprintf(L"%s <subcommand> <option>\n", f.substr(f.find_last_of(L"\\")+1).c_str());
#ifdef PYTHON_ENABLE
		wprintf(L"    pyfile <file>: Run python file\n");
		wprintf(L"    python: Run python interpreter\n");
#endif
		wprintf(L"    gui_serve: Run the GUI Serve\n");
		wprintf(L"    info_module: Module Information\n");
		wprintf(L"    run_module <module>: Run a module\n");
		wprintf(L"    run_all: Run all autorun-able modules\n");
		wprintf(L"        --export-csv: export file to csv named by ${Path}.${ModuleName}.csv\n");
		wprintf(L"    list_modules: List all modules\n");
	}

	static void RunPythonFile(const wchar_t* wpath) {
#ifdef  PYTHON_ENABLE

		std::wstring s = wpath;
		const char* path = StringUtils::ws2s(s).c_str();
		FILE* fp = fopen(path, "r");
		if (fp == NULL) {
			printf("Error open file %d\n",GetLastError());
			return;
		}
		int re = PyRun_SimpleFile(fp, path);
		fclose(fp);
#endif //  PYTHON_ENABLE
	}

	static void GuiServer() {
		Serve();
	}
	static std::wstring GetRunTypeAsString(RunType type) {
		if (type == ModuleAuto) {
			return L"ModuleAuto";
		}

		if (type == ModuleNeedArgs) {
			return L"ModuleNeedArgs";
		}

		if (type == ModuleNotImplement) {
			return L"ModuleNotImplement";
		}

		return L"ModuleUnknown";
	}

	static void ListModules() {
		auto mgr = ModuleMgr::GetMgr();
		wprintf(L"%-40s%s\n", L"ModuleName", L"RunType");
		for (auto& mod : mgr->modules) {
			auto name = mod->Path + L"." + mod->Name;
			wprintf(L"%-40s%s\n", name.c_str(), GetRunTypeAsString(mod->RunType).c_str());
		}
	}

	static void RunModule(wchar_t* moduleName,int len_args,wchar_t** args) {
		auto mgr = ModuleMgr::GetMgr();
		for (auto& mod : mgr->modules) {
			auto fullPath = mod->Path + L"." + mod->Name;
			if (fullPath == moduleName) {
				if (mod->RunType == ModuleNotImplement) {
					wprintf(L"This module is not impl\n...");
					wprintf(L"Sorry for waiting update...\n");
					continue;
				}
				Module::Args parameters;
				for (int i = 0; i < len_args; i++) {
					auto _kv = StringUtils::Trim(args[i]);
					auto kv = StringUtils::StringSplit(_kv, L"=");
					parameters[StringUtils::ws2s(kv[0])] = StringUtils::ws2s(kv[1]);
				}
				mod->SetArgs(parameters);
				ResultSet* res = mod->ModuleRun();
				if (res->type == ERROR_MESSAGE) {
					printf("[Error]: %s\n", res->GetErrorMessage().c_str());
					delete res;
					return;
				}
				if (res == nullptr) {
					return;
				}
				auto json = res->ToJsonObject();
				auto data = json["Data"];
				int size = 0;
				auto orders = res->GetMapOrder();
				for (auto &key : orders) {
					printf("%-30s ", key.c_str());
					size = data[key].size();
				}
				printf("\n");
				for (int i = 0; i < size; i++) {
					for (auto &key : orders) {
						auto member = data[key][i];
						wprintf(L"%-30s ", StringUtils::s2ws(member.asCString()).c_str());
					}
					printf("\n");
				}
				delete res;
				return;
			}
		}
	}

	static void RunAllModules(int len_args, wchar_t** args) {
		auto mgr = ModuleMgr::GetMgr();
		for (auto& mod : mgr->modules) {
			if (mod->RunType != ModuleAuto) {
				continue;
			}
			wprintf(L"%s Module Running...\n", mod->Name.c_str());
			ResultSet* res = mod->ModuleRun();
			if (res == nullptr) {
				wprintf(L"%s Module Ending...\n", mod->Name.c_str());
				return;
			}
			auto json = res->ToJsonObject();
			auto data = json["Data"];
			int size = 0;
			auto orders = res->GetMapOrder();
			for (auto& key : orders) {
				printf("%-30s ", key.c_str());
				size = data[key].size();
			}
			printf("\n");
			for (int i = 0; i < size; i++) {
				for (auto& key : orders) {
					auto member = data[key][i];
					wprintf(L"%-30s ", StringUtils::s2ws(member.asCString()).c_str());
				}
				printf("\n");
			}

			for (int i = 0; i < len_args; i++) {
				if (lstrcmpW(args[i], L"--export-csv")==0) {
					std::wstring filename = mod->Path + L"." + mod->Name + L".csv";
					auto file = GTFileUtils::Open(filename.c_str(), L"w");
					auto s = "\xef\xbb\xbf"+res->ToCsvString();
					file->WriteBytes(0, (PBYTE)s.c_str(), s.size());
					delete file;
				}
			}
			delete res;
			wprintf(L"%s Module Ending...\n", mod->Name.c_str());
		}

	}

	static void InfoModule(wchar_t* moduleName) {
		auto mgr = ModuleMgr::GetMgr();
		Module* targetModule = NULL;
		for (auto& mod : mgr->modules) {
			auto name = mod->Path + L"." + mod->Name;
			if (name == moduleName) {
				targetModule = mod;
				break;
			}
		}

		if (targetModule == NULL) {
			wprintf(L"Please select right module,the %s doesn't exist.\n",moduleName);
			return;
		}

		auto metaInfo = targetModule->GetModuleMetaJson();
		Json::StyledWriter writer;
		std::string output = writer.write(metaInfo);
		printf("%s\n", output.c_str());
		return;
	}
	
	static void Cmd() {

	}

	static void test() {
		FileInfo cmdFile(L"C:\\Windows\\System32\\cmd.exe");
		GTTime time = cmdFile.GetCreateTime();
		wprintf(L"%s\n", time.ToISO8601().c_str());
		return;
	}

	static void ListPaths() {
		auto mgr = ModuleMgr::GetMgr();
		std::set<std::wstring> paths;
		for (auto mod : mgr->modules) {
			paths.insert(mod->Path);
		}

		for (auto& path : paths) {
			wprintf(L"%s\n", path.c_str());
		}
	}
	static void MainArgs(int argc,wchar_t** argv) {
		setlocale(LC_ALL, "chs");
#ifdef PYTHON_ENABLE
		initialize init;
#endif // PYTHON_ENABLE
		if (argc < 2) {
			help(argv[0]);
			return;
		}

		std::wstring subcmd = argv[1];
		subcmd = StringUtils::Trim(subcmd);
		if (subcmd == L"pyfile") {
#ifdef PYTHON_ENABLE
			if (argc < 3) {
				wprintf(L"%s pyfile <pyfile_path>\n", argv[0]);
				return;
			}

			std::wstring path = argv[2];
			RunPythonFile(path.c_str());
#endif // PYTHON_ENABLE
			return;

		}
		else if (subcmd == L"gui_serve") {
			GuiServer();
			return;
		}
		if (subcmd == L"list_modules") {
			ListModules();
			return;
		}
		else if (subcmd == L"run_module") {
			if (argc < 3) {
				wprintf(L"Usage:%s run_module <exist_module>\n",argv[0]);
				return;
			}
			RunModule(argv[2], argc - 3, &argv[3]);
		}
		else if (subcmd == L"info_module") {
			if (argc < 3) {
				wprintf(L"Usage:%s info_module <exist_module>\n",argv[0]);
				return;
			}
			InfoModule(argv[2]);
		}
		else if (subcmd == L"python") {
#ifdef PYTHON_ENABLE
			Py_Main(argc - 1, &argv[1]);
#endif // PYTHON_ENABLE
		}
		else if (subcmd == L"test") {
			return ;
		}
		else if (subcmd == L"list_path") {

		}
		else if (subcmd == L"run_all") {
			RunAllModules(argc - 2, &argv[2]);
		}
		else if (subcmd == L"help") {
			help(argv[0]);
		}
		else if (subcmd == L"cmd") {

		}
	}
};