#include "KernelUtils.h"


int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
#ifdef PYTHON_ENABLE
	initialize init;
#endif // PYTHON_ENABLE
    return 0;
}