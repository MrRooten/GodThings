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
#include "PEInfo.h"
#include "Network.h"
#include "DriverInfo.h"

int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
	initialize init;
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}