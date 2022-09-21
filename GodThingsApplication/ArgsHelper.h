#pragma once
#include <string>
#include <set>
#include "PythonUtils.h"
#include "FileInfo.h"
#include "utils.h"
#include "OtherInfo.h"
#include "EvtInfo.h"
class ArgsHelper {
public:
	static void help(wchar_t *file) {
		std::wstring f(file);

		wprintf(L"%s <subcommand> <option>\n", f.substr(f.find_last_of(L"\\")+1).c_str());
		wprintf(L"    pyfile <file>: Run python file\n");
#ifdef PYTHON_ENABLE
		wprintf(L"    python: Run python interpreter\n");
#endif
		wprintf(L"    gui_serve: Run the GUI Serve\n");
		wprintf(L"    info_module: List the Module Information\n");
		wprintf(L"    run_module <module>: Run a module\n");
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

	static void ListModules() {
		auto mgr = ModuleMgr::GetMgr();
		for (auto& mod : mgr->modules) {
			wprintf(L"%s.%s\n", mod->Path.c_str(),mod->Name.c_str());
		}
	}

	static void RunModule(wchar_t* moduleName,int len_args,wchar_t** args) {
		auto mgr = ModuleMgr::GetMgr();
		for (auto& mod : mgr->modules) {
			if (mod->Name == moduleName) {
				Module::Args parameters;
				for (int i = 0; i < len_args; i++) {
					auto _kv = StringUtils::Trim(args[i]);
					auto kv = StringUtils::StringSplit(_kv, L"=");
					parameters[StringUtils::ws2s(kv[0])] = StringUtils::ws2s(kv[1]);
				}
				mod->SetArgs(parameters);
				ResultSet* res = mod->ModuleRun();
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

	static void InfoModule(wchar_t* moduleName) {
		auto mgr = ModuleMgr::GetMgr();
		Module* targetModule = NULL;
		for (auto& mod : mgr->modules) {
			if (mod->Name == moduleName) {
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
			if (argc < 3) {
				wprintf(L"%s pyfile <pyfile_path>\n", argv[0]);
				return;
			}

			std::wstring path = argv[2];
			RunPythonFile(path.c_str());
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
			test();
		}
		else if (subcmd == L"list_path") {

		}
	}
};