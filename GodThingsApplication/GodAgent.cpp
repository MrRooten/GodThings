#include "KernelUtils.h"
#include "ArgsHelper.h"



int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
#ifdef PYTHON_ENABLE
	initialize init;
#endif // PYTHON_ENABLE
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}