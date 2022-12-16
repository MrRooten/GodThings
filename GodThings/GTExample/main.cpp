#include "KernelUtils.h"
#include "ArgsHelper.h"
#include "ExtendModules.h"
void extendInit() {
    new BAMParse();
    new LastShutdown();
}

int wmain(int argc, wchar_t* argv[]) {
    InitKernelUtils();
    extendInit();
#ifdef PYTHON_ENABLE
    initialize init;
#endif // PYTHON_ENABLE
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}