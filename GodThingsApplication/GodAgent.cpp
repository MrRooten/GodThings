
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <future>
#include "threadpool/thread_pool.h"
#include "PythonUtils.h"
#include "Module.h"
#include "ProcServer.h"
//#include "ProcServer.h"
// runs in a new thread
class VM {
public:
    PyInterpreterState* interp;
    VM(PyInterpreterState* interp) {
        this->interp = interp;
    }

    void exec(const char* code) {
        sub_interpreter::thread_scope scope(this->interp);
        PythonUtils::ExecString("print(123)");
    }
};

// runs in a new thread
void f(PyInterpreterState* interp, const char* tname)
{
    std::string code = R"PY(
from __future__ import print_function
import sys
print("TNAME: sys.xxx={}".format(getattr(sys, 'xxx', 'attribute not set')))
    )PY";

    code.replace(code.find("TNAME"), 5, tname);
    PyArgs a;
    sub_interpreter::thread_scope scope(interp);
    PythonUtils::ExecString("import process_internal\nprint(process_internal.get_pids())");
}
void test() {
    sub_interpreter s1;
}


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
    //PythonModule* m = new PythonModule(L"D:\\SourceCodes\\qwer1");
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
#include "parse.h"
#include "ProcessUtils.h"
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
int main() {
    InitKernelUtils();
    Serve();
    //test2();
    //test3();
    //GetTCPConnection();
    
    return 0;
}