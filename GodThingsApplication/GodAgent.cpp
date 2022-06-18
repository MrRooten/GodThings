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

int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}