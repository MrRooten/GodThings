#include "KernelUtils.h"
#include "ArgsHelper.h"
#include "ExtendModules.h"

void extendInit() {
    new BAMParse();
    new LastShutdown();
    new JumpListData();
    new ListSSP();
    new RDPSessions();
    new RDPClientSess();
    new LoadedFiles();
    new File();
    new ProcessHandle();
    new StaticInfo();
    new NetInterfaces();
}


#include <windows.h>
#include <stdio.h>



int wmain(int argc, wchar_t* argv[]) {
    auto _ = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    InitKernelUtils();
    extendInit();
#ifdef PYTHON_ENABLE
    initialize init;
#endif // PYTHON_ENABLE
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}