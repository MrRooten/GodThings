#pragma once
#include <string>
#include "PythonUtils.h"
class ArgsHelper {
public:
	static void help(char *file) {
		printf("\n%s <subcommand> <option>\n", file);
		printf("\tpyfile <file>\n");
		printf("\t\tRun python file\n");
	}

	static void RunPythonFile(const char* path) {
		
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

	static void RunModule(char* moduleName,int argc,char** args) {

	}

	static void InfoModule(char* moduleName) {

	}

	static void MainArgs(int argc,char** argv) {
		initialize init;
		if (argc < 2) {
			help(argv[0]);
			return;
		}

		std::string subcmd = argv[1];
		if (subcmd == "pyfile") {
			if (argc < 3) {
				printf("%s pyfile <pyfile_path>\n", argv[0]);
				return;
			}

			std::string path = argv[2];
			RunPythonFile(path.c_str());
			return;
		}
		else if (subcmd == "gui_serve") {
			GuiServer();
			return;
		}
		ModuleMgr* mgr = ModuleMgr::GetMgr();
		if (subcmd == "list_modules") {
			ListModules();
			return;
		}
		else if (subcmd == "run_module") {

		}
		else if (subcmd == "info_module") {

		}

		help(argv[0]);
	}
};