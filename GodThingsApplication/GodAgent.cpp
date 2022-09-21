#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <future>
#include "threadpool/thread_pool.h"
#include "PythonUtils.h"
#include "Module.h"
#include "ProcServer.h"
#include "parse.h"
#include "ProcessUtils.h"
#include "ArgsHelper.h"



int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
#ifdef PYTHON_ENABLE
	initialize init;
#endif // PYTHON_ENABLE
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}