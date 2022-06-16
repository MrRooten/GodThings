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
/*
int test2()
{
    initialize init;

    
    PyRun_SimpleString(R"PY(
# set sys.xxx, it will only be reflected in t4, which runs in the context of the main interpreter
from __future__ import print_function
import sys
sys.xxx = ['abc']
print('main: setting sys.xxx={}'.format(sys.xxx))
    )PY");
    
    sub_interpreter ss[30];
    PythonModule* m = new PythonModule(L"D:\\SourceCodes\\qwer1");
    std::vector<std::jthread*> js;
    
    enable_threads_scope t;
    for (int i = 0; i < 10; i++) {
        js.push_back(new std::jthread(f, ss[i].interp(), std::to_string(i).c_str()));
    }
    for (auto& j : js) {
        j->join();
    }
    for (auto& j : js) {
        delete j;
    }
    return 0;
}

void test3() {
    InitKernelUtils();
    HANDLE a = GTOpenProcess(4,PROCESS_ALL_ACCESS);
    if (GetLastError() == 0) {
        printf("Open Success %p\n", a);
    }
    else {
        printf("Open Failed,%d", GetLastError());
    }
    PROCESS_MEMORY_COUNTERS memory;
    if (GetProcessMemoryInfo(a, &memory, sizeof(memory))) {
        printf("yes\n");
    }
    
}
*/
int wmain(int argc,wchar_t* argv[]) {
    InitKernelUtils();
    // create a parser
    ArgsHelper::MainArgs(argc, argv);
    return 0;
}