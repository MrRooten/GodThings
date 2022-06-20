#pragma once
#include <string>
#include "PythonUtils.h"
class ArgsHelper {
public:
	static void help(wchar_t *file) {
		std::wstring f(file);

		wprintf(L"%s <subcommand> <option>\n", f.substr(f.find_last_of(L"\\")+1).c_str());
		wprintf(L"    pyfile <file>: Run python file\n");
		wprintf(L"    interpreter: Run python interpreter\n");
		wprintf(L"    gui_serve: Run the GUI Serve\n");
		wprintf(L"    info_module: List the Module Information\n");
	}

	static void RunPythonFile(const wchar_t* wpath) {
		std::wstring s = wpath;
		const char* path = StringUtils::ws2s(s).c_str();
		FILE* fp = fopen(path, "r");
		if (fp == NULL) {
			printf("Error open file %d\n",GetLastError());
			return;
		}
		int re = PyRun_SimpleFile(fp, path);
		fclose(fp);
	}

	static void GuiServer() {
		Serve();
	}

	static void ListModules() {
		auto mgr = ModuleMgr::GetMgr();
		for (auto& mod : mgr->modules) {
			wprintf(L"%s\n", mod->Name.c_str());
		}
	}

	static void RunModule(wchar_t* moduleName,int argc,wchar_t** args) {

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

	static void MainArgs(int argc,wchar_t** argv) {
		initialize init;
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
		else if (subcmd == L"interpreter") {
			Py_Main(argc - 1, &argv[1]);
		}

	}
};