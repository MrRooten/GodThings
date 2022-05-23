#include "PythonUtils.h"
#include <string>
#include <vector>
#include <thread>
#include "StringUtils.h"
#include "ObjectInfo.h"
#include "RegistryUtils.h"
namespace PyProcessInfoModule {
    PyObject* GetPids(PyObject* self, PyObject* args) {
        PyObject* list = PyList_New(0);
        mgr = new ProcessManager();
        mgr->UpdateInfo();
        for (auto item : mgr->processesMap) {
            PyList_Append(list, PyLong_FromLong(item.first));
        }
        return list;
    }

    PyObject* GetProcessName(PyObject* self, PyObject* args) {
        int pid;

        if (!PyArg_ParseTuple(args, "i", &pid)) {
            return NULL;
        }
        std::wstring processName;
        if (mgr != NULL) {
            processName = mgr->processesMap[pid]->processName;
        }
        else {
            Process *process = new Process(pid);
            process->SetProcessImageState();
            processName = process->imageState->imageFileName;
            if (processName.size() == 0) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //Throw error
                    PyUnicode_FromString("");;
                }
                mgr->UpdateInfo();
                processName = mgr->processesMap[pid]->processName;
            }
        }

        PyObject* pyProcessName;
        pyProcessName = PyUnicode_FromString(StringUtils::ws2s(processName).c_str());
        return pyProcessName;
    }


    PyObject* GetProcessSecurityState(PyObject* self,PyObject* args) {
        int pid;
        PyObject* SecurityStateSerial = PyList_New(0);
        if (!PyArg_ParseTuple(args, "i", &pid)) {
            SecurityStateSerial;
        }
        
        Process* process = NULL;
        if (mgr != NULL) {
            if (mgr->processesMap.count(pid) > 0) {
                process = mgr->processesMap[pid];
            }
            else {
                //THROW ERROR
                SecurityStateSerial;
            }
        }
        
        if (process == NULL) {
            if (mgr == NULL) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //THROW ERROR
                    SecurityStateSerial;
                }
            }
            process = mgr->processesMap[pid];
        }
        if (process == NULL) {
            PyDict_New();
        }
        DWORD status = process->SetProcessSecurityState();
        if (status != ERROR_SUCCESS) {
            //THROW ERROR
            PyDict_New();
        }
        //SecurityState->groups serialize
        PyObject* groups = PyList_New(0);
        auto _groups = process->securityState->GetSIDsString();
        for (auto _group : _groups) {
            PyObject* group = PyUnicode_FromString(StringUtils::ws2s(_group).c_str());
            PyList_Append(groups,group);
            Py_XDECREF(group);
        }
        //SecurityState->Session serialize
        PyObject* session = PyLong_FromLong((long)process->securityState->Session);
        //SecurityState->Privilege serialize
        auto _privileges = process->securityState->GetPrivilegesAsString();
        PyObject* privileges = PyList_New(0);
        for (auto _privilege : _privileges) {
            PyObject* privilege = PyUnicode_FromString(StringUtils::ws2s(_privilege).c_str());
            PyList_Append(privileges, privilege);
            Py_XDECREF(privilege);
        }
        //SecurityState->integrity serialize
        PyObject* integrity = PyUnicode_FromString(StringUtils::ws2s(process->securityState->GetIntegrityAsString()).c_str());

        //Serialize the SecurityState
        PyList_Append(SecurityStateSerial, groups);
        Py_XDECREF(groups);
        PyList_Append(SecurityStateSerial, session);
        Py_XDECREF(session);
        PyList_Append(SecurityStateSerial, privileges);
        Py_XDECREF(privileges);
        PyList_Append(SecurityStateSerial, integrity);
        Py_XDECREF(integrity);
        return SecurityStateSerial;
    }

    PyObject* PyProcessInfoModule::GetProcessMemoryState(PyObject* self,PyObject* args) {
        int pid;
        PyObject* MemoryStateSerial = PyList_New(0);
        if (!PyArg_ParseTuple(args, "i", &pid)) {
            MemoryStateSerial;
        }

        Process* process = NULL;
        if (mgr != NULL) {
            if (mgr->processesMap.count(pid) > 0) {
                process = mgr->processesMap[pid];
            }
            else {
                //THROW ERROR
                MemoryStateSerial;
            }
        }

        if (process == NULL) {
            if (mgr == NULL) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //THROW ERROR
                    MemoryStateSerial;
                }
            }
            process = mgr->processesMap[pid];
        }
        if (process == NULL) {
            MemoryStateSerial;
        }
        
        DWORD status = process->SetProcessMemoryState();
        if (status != ERROR_SUCCESS) {
            MemoryStateSerial;
        }
        MemoryStateSerial = PyList_New(0);
        auto f = [MemoryStateSerial, process](SIZE_T value) {
            PyObject* pyValue = PyLong_FromLongLong(value);
            PyList_Append(MemoryStateSerial, pyValue);
            Py_XDECREF(pyValue);
        };
        f(process->memoryState->PeakVirtualSize);
        f(process->memoryState->VirtualSize);
        f(process->memoryState->PageFaultCount);
        f(process->memoryState->PeakVirtualSize);
        f(process->memoryState->WorkingSetSize);
        f(process->memoryState->QuotaPeakPagedPoolUsage);
        f(process->memoryState->QuotaPagedPoolUsage);
        f(process->memoryState->QuotaPeakNonPagedPoolUsage);
        f(process->memoryState->QuotaNonPagedPoolUsage);
        f(process->memoryState->PagefileUsage);
        f(process->memoryState->PeakPagefileUsage);
        f(process->memoryState->PrivateUsage);
        f(process->memoryState->PrivateWorkingSetSize);
        f(process->memoryState->SharedCommitUsage);
        return MemoryStateSerial;
    }

    PyObject* GetProcessIOState(PyObject* self, PyObject* args) {
        PyObject* IoStateSerial;
        int pid;
        if (!PyArg_ParseTuple(args, "i", &pid)) {
            PyList_New(0);
        }

        Process* process = NULL;
        if (mgr != NULL) {
            if (mgr->processesMap.count(pid) > 0) {
                process = mgr->processesMap[pid];
            }
            else {
                //THROW ERROR
                PyList_New(0);
            }
        }

        if (process == NULL) {
            if (mgr == NULL) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //THROW ERROR
                    PyList_New(0);
                }
            }
            process = mgr->processesMap[pid];
        }
        if (process == NULL) {
            PyList_New(0);
        }

        DWORD status = process->SetProcessIOState();
        if (status != ERROR_SUCCESS) {
            PyList_New(0);
        }

        IoStateSerial = PyList_New(0);
        std::string _priority;
        switch (process->ioState->priority) {
        case IoPriorityVeryLow: {
            _priority = "IoPriorityVeryLow";
            break;
        }
        case IoPriorityLow: {
            _priority = "IoPriorityLow";
            break;
        }
        case IoPriorityNormal: {
            _priority = "IoPriorityNormal";
            break;
        }
        case IoPriorityHigh: {
            _priority = "IoPriorityHigh";
            break;
        }
        case IoPriorityCritical: {
            _priority = "IoPriorityCritical";
            break;
        }
        default: {
            break;
        }
        }
        auto s = [IoStateSerial, process](const char* value) {
            PyObject* pyValue = PyUnicode_FromString(value);
            PyList_Append(IoStateSerial, pyValue);
            Py_XDECREF(pyValue);
        };

        auto f = [IoStateSerial, process](SIZE_T value) {
            PyObject* pyValue = PyLong_FromLongLong(value);
            PyList_Append(IoStateSerial, pyValue);
            Py_XDECREF(pyValue);
        };
        s(_priority.c_str());
        f(process->ioState->ReadOperationCount);
        f(process->ioState->WriteOperationCount);
        f(process->ioState->OtherOperationCount);
        f(process->ioState->ReadTransferCount);
        f(process->ioState->WriteTransferCount);
        f(process->ioState->OtherTransferCount);

        return IoStateSerial;
    }

    PyObject* GetProcessCPUState(PyObject* self, PyObject* args) {
        PyObject* CPUStateSerial = NULL;
        int pid;
        if (!PyArg_ParseTuple(args, "i", &pid)) {
            PyList_New(0);
        }

        Process* process = NULL;
        if (mgr != NULL) {
            if (mgr->processesMap.count(pid) > 0) {
                process = mgr->processesMap[pid];
            }
            else {
                //THROW ERROR
                PyList_New(0);
            }
        }

        if (process == NULL) {
            if (mgr == NULL) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //THROW ERROR
                    PyList_New(0);
                }
            }
            process = mgr->processesMap[pid];
        }
        if (process == NULL) {
            PyList_New(0);
        }

        DWORD status = process->SetProcessIOState();
        if (status != ERROR_SUCCESS) {
            PyList_New(0);
        }

        CPUStateSerial = PyList_New(0);
        status = process->SetProcessCPUState();
        if (status != 0) {
            PyList_New(0);
        }
        auto f = [CPUStateSerial, process](SIZE_T value) {
            PyObject* pyValue = PyLong_FromLongLong(value);
            PyList_Append(CPUStateSerial, pyValue);
            Py_XDECREF(pyValue);
        };
        f(process->latestCpuState->createTime.dwLowDateTime);
        f(process->latestCpuState->createTime.dwHighDateTime);
        f(process->latestCpuState->exitTime.dwLowDateTime);
        f(process->latestCpuState->exitTime.dwHighDateTime);
        f(process->latestCpuState->kernelTime.dwLowDateTime);
        f(process->latestCpuState->kernelTime.dwHighDateTime);
        f(process->latestCpuState->userTime.dwLowDateTime);
        f(process->latestCpuState->userTime.dwHighDateTime);
        std::string _priority;
        switch (process->latestCpuState->priority) {
        case PROCESS_PRIORITY_CLASS_UNKNOWN: {
            _priority = "PROCESS_PRIORITY_CLASS_UNKNOWN";
            break;
        }
        case PROCESS_PRIORITY_CLASS_IDLE: {
            _priority = "PROCESS_PRIORITY_CLASS_IDLE";
            break;
        }
        case PROCESS_PRIORITY_CLASS_NORMAL: {
            _priority = "PROCESS_PRIORITY_CLASS_NORMAL";
            break;
        }
        case PROCESS_PRIORITY_CLASS_HIGH: {
            _priority = "PROCESS_PRIORITY_CLASS_HIGH";
            break;
        }
        case PROCESS_PRIORITY_CLASS_REALTIME: {
            _priority = "PROCESS_PRIORITY_CLASS_REALTIME";
            break;
        }
        case PROCESS_PRIORITY_CLASS_BELOW_NORMAL: {
            _priority = "PROCESS_PRIORITY_CLASS_BELOW_NORMAL";
            break;
        }
        case PROCESS_PRIORITY_CLASS_ABOVE_NORMAL: {
            _priority = "PROCESS_PRIORITY_CLASS_ABOVE_NORMAL";
            break;
        }
        default: {
            break;
        }
        }

        auto s = [CPUStateSerial, process](const char* value) {
            PyObject* pyValue = PyUnicode_FromString(value);
            PyList_Append(CPUStateSerial, pyValue);
            Py_XDECREF(pyValue);
        };
        s(_priority.c_str());


        return CPUStateSerial;
    }

    PyObject* GetProcessHandleState(PyObject* self, PyObject* args) {
        PyObject* HandleStateSerial;
        int pid;
        if (!PyArg_ParseTuple(args, "i", &pid)) {
            PyList_New(0);
        }

        Process* process = NULL;
        if (mgr != NULL) {
            if (mgr->processesMap.count(pid) > 0) {
                process = mgr->processesMap[pid];
            }
            else {
                //THROW ERROR
                PyList_New(0);
            }
        }

        if (process == NULL) {
            if (mgr == NULL) {
                mgr = new ProcessManager();
                if (mgr == NULL) {
                    //THROW ERROR
                    PyList_New(0);
                }
            }
            process = mgr->processesMap[pid];
        }
        if (process == NULL) {
            PyList_New(0);
        }

        DWORD status = process->SetProcessHandleState();
        if (status != ERROR_SUCCESS) {
            PyList_New(0);
        }

        HandleStateSerial = PyList_New(0);
        PyObject* handles = PyList_New(0);
        
        for (size_t i = 0; i < process->handleState->handles->NumberOfHandles; i++) {
            PyObject* item = PyList_New(0);
            auto f = [item](SIZE_T value) {
                PyObject* pyValue = PyLong_FromLongLong(value);
                PyList_Append(item, pyValue);
                Py_XDECREF(pyValue);
            };

            auto s = [item](const char* value) {
                PyObject* pyValue = PyUnicode_FromString(value);
                PyList_Append(item, pyValue);
                Py_XDECREF(pyValue);
            };
            s(StringUtils::ws2s(ObjectInfo::GetTypeName(process->handleState->handles->Handles[i].HandleValue)).c_str());
            s(StringUtils::ws2s(ObjectInfo::GetObjectName(process->handleState->handles->Handles[i].HandleValue)).c_str());
            f(process->handleState->handles->Handles[i].HandleCount);
            f(process->handleState->handles->Handles[i].PointerCount);
            f(process->handleState->handles->Handles[i].GrantedAccess);
            PyList_Append(handles, item);
            Py_XDECREF(item);
        }
        PyList_Append(HandleStateSerial, handles);
        Py_XDECREF(handles);
        return HandleStateSerial;
    }

    PyObject* ProcessInfoModuleInit() {
        return PyModule_Create(&moduleDef);
    }

    
};
#include "SystemInfo.h"

PyObject* PySystemInfoModule::GetSystemBasicInfo(PyObject* self, PyObject* args) {
    SystemInfo info;
    DWORD status = info.SetBasicInfo();
    if (status != ERROR_SUCCESS) {
        PyDict_New();
    }

    info.pBasicInfo;
    PyObject* basicInfo = PyDict_New();
    auto fsi = [basicInfo](const char* key, ULONG64 value) {
        PyObject* pyKey = PyUnicode_FromString(key);
        PyObject* pyValue = PyLong_FromUnsignedLongLong(value);
        PyDict_SetItem(basicInfo, pyKey, pyValue);
        Py_XDECREF(pyKey);
        Py_XDECREF(pyValue);
    };
    fsi("TimeResolution",info.pBasicInfo->TimerResolution);
    fsi("PageSize",info.pBasicInfo->PageSize);
    fsi("NumerOfPhysicalPages",info.pBasicInfo->NumberOfPhysicalPages);
    fsi("LowestPhysicalPageNumber",info.pBasicInfo->LowestPhysicalPageNumber);
    fsi("HighestPhysicalPageNumber",info.pBasicInfo->HighestPhysicalPageNumber);
    fsi("AllocationGranularity",info.pBasicInfo->AllocationGranularity);
    fsi("MinimumUserModeAddress",info.pBasicInfo->MinimumUserModeAddress);
    fsi("MaximumUserModeAddress",info.pBasicInfo->MaximumUserModeAddress);
    fsi("ActiveProcessorsAffinityMask",info.pBasicInfo->ActiveProcessorsAffinityMask);
    fsi("NumberOfProcessors",info.pBasicInfo->NumberOfProcessors);
    return basicInfo;
}

PyObject* PySystemInfoModule::GetProcessorInfo(PyObject* self, PyObject* args) {
    SystemInfo info;
    PyObject* processorInfo;
    DWORD status = info.SetProcessorInfo();
    if (status != ERROR_SUCCESS) {
        PyDict_New();
    }
    
    processorInfo = PyDict_New();
    auto fsi = [processorInfo](const char* key, ULONG64 value) {
        PyObject* pyKey = PyUnicode_FromString(key);
        PyObject* pyValue = PyLong_FromUnsignedLongLong(value);
        PyDict_SetItem(processorInfo, pyKey, pyValue);
        Py_XDECREF(pyKey);
        Py_XDECREF(pyValue);
    };

    auto fss = [processorInfo](const char* key, const char *value) {
        PyObject* pyKey = PyUnicode_FromString(key);
        PyObject* pyValue = PyUnicode_FromString(value);
        PyDict_SetItem(processorInfo, pyKey, pyValue);
        Py_XDECREF(pyKey);
        Py_XDECREF(pyValue);
    };
    fsi("ProcessorLevel",info.pProcessorInfo->ProcessorLevel);
    fsi("ProcessorRevision", info.pProcessorInfo->ProcessorRevision);
    fsi("MaximumProcessors", info.pProcessorInfo->MaximumProcessors);
    fsi("ProcessorFeatureBits", info.pProcessorInfo->ProcessorFeatureBits);
    fss("ProcessorArchitecture", StringUtils::ws2s(info.GetProcessorArch()).c_str());
    return processorInfo;
}
void _dict_insert_help(PyObject* dict, PyObject* key, PyObject* value) {
    PyDict_SetItem(dict, key, value);
    Py_XDECREF(key);
    Py_XDECREF(value);
};

void _list_insert_help(PyObject* list, PyObject* value) {
    PyList_Append(list, value);
    Py_XDECREF(value);
}
PyObject* PySystemInfoModule::GetPerfInfo(PyObject* self, PyObject* args) {
    SystemInfo info;
    PyObject* perfInfo;
    DWORD status = info.SetPerformanceInfo();
    if (status != ERROR_SUCCESS) {
        return PyDict_New();
    }

    perfInfo = PyDict_New();
    PyObject* idleTime = PyList_New(0);
    _list_insert_help(idleTime, PyLong_FromLongLong(info.pPerformanceInfo->IdleProcessTime.HighPart));
    _list_insert_help(idleTime, PyLong_FromLongLong(info.pPerformanceInfo->IdleProcessTime.LowPart));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IdleProcessTime"), idleTime);
    PyObject* ioReadTransferCount = PyList_New(0);
    _list_insert_help(ioReadTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoReadTransferCount.HighPart));
    _list_insert_help(ioReadTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoReadTransferCount.LowPart));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoReadTransferCount"), ioReadTransferCount);
    PyObject* IoWriteTransferCount = PyList_New(0);
    _list_insert_help(IoWriteTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoWriteTransferCount.HighPart));
    _list_insert_help(IoWriteTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoWriteTransferCount.LowPart));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoWriteTransferCount"), IoWriteTransferCount);
    PyObject* IoOtherTransferCount = PyList_New(0);
    _list_insert_help(IoOtherTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoOtherTransferCount.HighPart));
    _list_insert_help(IoOtherTransferCount, PyLong_FromLongLong(info.pPerformanceInfo->IoOtherTransferCount.LowPart));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoOtherTransferCount"), IoOtherTransferCount);
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoReadOperationCount"), PyLong_FromLongLong(info.pPerformanceInfo->IoReadOperationCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoWriteOperationCount"), PyLong_FromLongLong(info.pPerformanceInfo->IoWriteOperationCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("IoOtherOperationCount"), PyLong_FromLongLong(info.pPerformanceInfo->IoOtherOperationCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("AvailablePages"), PyLong_FromLongLong(info.pPerformanceInfo->AvailablePages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CommittedPages"), PyLong_FromLongLong(info.pPerformanceInfo->CommittedPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CommitLimit"), PyLong_FromLongLong(info.pPerformanceInfo->CommitLimit));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PeakCommitment"), PyLong_FromLongLong(info.pPerformanceInfo->PeakCommitment));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PageFaultCount"), PyLong_FromLongLong(info.pPerformanceInfo->PageFaultCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CopyOnWriteCount"), PyLong_FromLongLong(info.pPerformanceInfo->CopyOnWriteCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("TransitionCount"), PyLong_FromLongLong(info.pPerformanceInfo->TransitionCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CacheTransitionCount"), PyLong_FromLongLong(info.pPerformanceInfo->CacheTransitionCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("DemandZeroCount"), PyLong_FromLongLong(info.pPerformanceInfo->DemandZeroCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PageReadCount"), PyLong_FromLongLong(info.pPerformanceInfo->PageReadCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PageReadIoCount"), PyLong_FromLongLong(info.pPerformanceInfo->PageReadIoCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CacheReadCount"), PyLong_FromLongLong(info.pPerformanceInfo->CacheReadCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CacheIoCount"), PyLong_FromLongLong(info.pPerformanceInfo->CacheIoCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("DirtyPagesWriteCount"), PyLong_FromLongLong(info.pPerformanceInfo->DirtyPagesWriteCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("DirtyWriteIoCount"), PyLong_FromLongLong(info.pPerformanceInfo->DirtyWriteIoCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("MappedPagesWriteCount"), PyLong_FromLongLong(info.pPerformanceInfo->MappedPagesWriteCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("MappedWriteIoCount"), PyLong_FromLongLong(info.pPerformanceInfo->MappedWriteIoCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PagedPoolPages"), PyLong_FromLongLong(info.pPerformanceInfo->PagedPoolPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("NonPagedPoolPages"), PyLong_FromLongLong(info.pPerformanceInfo->NonPagedPoolPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PagedPoolAllocs"), PyLong_FromLongLong(info.pPerformanceInfo->PagedPoolAllocs));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PagedPoolFrees"), PyLong_FromLongLong(info.pPerformanceInfo->PagedPoolFrees));
    _dict_insert_help(perfInfo, PyUnicode_FromString("NonPagedPoolAllocs"), PyLong_FromLongLong(info.pPerformanceInfo->NonPagedPoolAllocs));
    _dict_insert_help(perfInfo, PyUnicode_FromString("NonPagedPoolFrees"), PyLong_FromLongLong(info.pPerformanceInfo->NonPagedPoolFrees));
    _dict_insert_help(perfInfo, PyUnicode_FromString("FreeSystemPtes"), PyLong_FromLongLong(info.pPerformanceInfo->FreeSystemPtes));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ResidentSystemCodePage"), PyLong_FromLongLong(info.pPerformanceInfo->ResidentSystemCodePage));
    _dict_insert_help(perfInfo, PyUnicode_FromString("TotalSystemDriverPages"), PyLong_FromLongLong(info.pPerformanceInfo->TotalSystemDriverPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("TotalSystemCodePages"), PyLong_FromLongLong(info.pPerformanceInfo->TotalSystemCodePages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("NonPagedPoolLookasideHits"), PyLong_FromLongLong(info.pPerformanceInfo->NonPagedPoolLookasideHits));
    _dict_insert_help(perfInfo, PyUnicode_FromString("PagedPoolLookasideHits"), PyLong_FromLongLong(info.pPerformanceInfo->PagedPoolLookasideHits));
    _dict_insert_help(perfInfo, PyUnicode_FromString("AvailablePagedPoolPages"), PyLong_FromLongLong(info.pPerformanceInfo->AvailablePagedPoolPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ResidentSystemCachePage"), PyLong_FromLongLong(info.pPerformanceInfo->ResidentSystemCachePage));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ResidentPagedPoolPage"), PyLong_FromLongLong(info.pPerformanceInfo->ResidentPagedPoolPage));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ResidentSystemDriverPage"), PyLong_FromLongLong(info.pPerformanceInfo->ResidentSystemDriverPage));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastReadNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastReadNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastReadWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastReadWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastReadResourceMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastReadResourceMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastReadNotPossible"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastReadNotPossible));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastMdlReadNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastMdlReadNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastMdlReadWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastMdlReadWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastMdlReadResourceMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastMdlReadResourceMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcFastMdlReadNotPossible"), PyLong_FromLongLong(info.pPerformanceInfo->CcFastMdlReadNotPossible));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMapDataNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcMapDataNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMapDataWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcMapDataWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMapDataNoWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcMapDataNoWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMapDataWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcMapDataWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcPinMappedDataCount"), PyLong_FromLongLong(info.pPerformanceInfo->CcPinMappedDataCount));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcPinReadNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcPinReadNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcPinReadWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcPinReadWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcPinReadNoWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcPinReadNoWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcPinReadWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcPinReadWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcCopyReadNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcCopyReadNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcCopyReadWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcCopyReadWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcCopyReadNoWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcCopyReadNoWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcCopyReadWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcCopyReadWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMdlReadNoWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcMdlReadNoWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMdlReadWait"), PyLong_FromLongLong(info.pPerformanceInfo->CcMdlReadWait));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMdlReadNoWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcMdlReadNoWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcMdlReadWaitMiss"), PyLong_FromLongLong(info.pPerformanceInfo->CcMdlReadWaitMiss));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcReadAheadIos"), PyLong_FromLongLong(info.pPerformanceInfo->CcReadAheadIos));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcLazyWriteIos"), PyLong_FromLongLong(info.pPerformanceInfo->CcLazyWriteIos));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcLazyWritePages"), PyLong_FromLongLong(info.pPerformanceInfo->CcLazyWritePages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcDataFlushes"), PyLong_FromLongLong(info.pPerformanceInfo->CcDataFlushes));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcDataPages"), PyLong_FromLongLong(info.pPerformanceInfo->CcDataPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ContextSwitches"), PyLong_FromLongLong(info.pPerformanceInfo->ContextSwitches));
    _dict_insert_help(perfInfo, PyUnicode_FromString("FirstLevelTbFills"), PyLong_FromLongLong(info.pPerformanceInfo->FirstLevelTbFills));
    _dict_insert_help(perfInfo, PyUnicode_FromString("SystemCalls"), PyLong_FromLongLong(info.pPerformanceInfo->SystemCalls));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcTotalDirtyPages"), PyLong_FromLongLong(info.pPerformanceInfo->CcTotalDirtyPages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("CcDirtyPageThreshold"), PyLong_FromLongLong(info.pPerformanceInfo->CcDirtyPageThreshold));
    _dict_insert_help(perfInfo, PyUnicode_FromString("ResidentAvailablePages"), PyLong_FromLongLong(info.pPerformanceInfo->ResidentAvailablePages));
    _dict_insert_help(perfInfo, PyUnicode_FromString("SharedCommittedPages"), PyLong_FromLongLong(info.pPerformanceInfo->SharedCommittedPages));
    return perfInfo;
}

PyObject* PySystemInfoModule::SystemInfoModuleInit() {
    return PyModule_Create(&moduleDef);
}
bool PythonUtils::isInitialize = FALSE;
char* PythonUtils::PyStringToString(PyObject* object) {
    PyObject* ItemString = PyUnicode_AsEncodedString(object, "utf-8", "~E~");
    char* bytes = PyBytes_AS_STRING(ItemString);
    return bytes;
}
std::string PythonUtils::GetLastErrorAsString() {
    return PythonUtils::PyStringToString(PyObject_Repr(PythonUtils::GetLastError()));
}
bool PythonUtils::Initialize() {
    bool res = true;
    try {
        Py_Initialize();
        res = true;
    }
    catch (...) {
        res = false;
    }
    return res;
}
bool PythonUtils::Finalize() {
    bool res = true;
    try {
        Py_FinalizeEx();
    }
    catch (...) {
        res = false;
    }
    return res;
}
DWORD PythonUtils::ExecString(const char* pyString) {
    PyImport_AppendInittab("process_internal", PyProcessInfoModule::ProcessInfoModuleInit);
    PyImport_AppendInittab("system_internal", PySystemInfoModule::SystemInfoModuleInit);
    Py_Initialize();
    //PyRun_SimpleFile(fp, pyFile.c_str());
    PyRun_SimpleString(pyString);
    printf("Error:%s\n", GetLastErrorAsString().c_str());
    return 0;
}
#include "StringUtils.h"
DWORD PythonUtils::LoadFile(const char* pyFile) {
    PyImport_AppendInittab("process_internal", &PyProcessInfoModule::ProcessInfoModuleInit);
    PyImport_AppendInittab("system_internal", &PySystemInfoModule::SystemInfoModuleInit);
    Py_Initialize();
    FILE* fp = fopen(pyFile, "r");
    PyRun_SimpleFile(fp, pyFile);
    
    //PyRun_SimpleString("import process\nprint(process.ProcessesManager.get_pids())");
}


DWORD PythonUtils::RunFunction(PyObjectCallback callback,const char* cstr_file, const char* cstr_function, PyArgs &args) {
    PyObject* pName, * pModule, * pFunc;
    PyObject* pArgs, * pValue = NULL;
    PyObject* pErrorObject = NULL;
    int res = 0;
    /*if (Py_IsInitialized() == false) {
        Py_Initialize();
    }*/
    std::string file(cstr_file);
    std::string function(cstr_function);
    std::string dir = file.substr(0,file.find_last_of('\\')+1);
    PyRun_SimpleString("import sys");
    PyObject* path = PySys_GetObject("path");
    PyList_Append(path, PyUnicode_FromString(dir.c_str()));
    
    //PyRun_SimpleString("print(sys.path)");
    file = file.substr(file.find_last_of("\\")+1);
    pName = PyUnicode_DecodeFSDefault(file.c_str());
    /* Error checking of pName left out */

    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, function.c_str());
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
            int lenArgs = args.size();
            pArgs = PyTuple_New(lenArgs);
            for (int i = 0; i < lenArgs; ++i) {
                /* pValue reference stolen here: */
                PyTuple_SetItem(pArgs, i, args[i]);
            }
            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);
            if (pValue != NULL) {
                //Py_XDECREF(pValue);
                //callback(pValue);
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                pValue = PythonUtils::GetLastError();
                
            }
        }
        else {
            if (PyErr_Occurred())
                pValue = PythonUtils::GetLastError();
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        pValue = PythonUtils::GetLastError();
    }
    //std::cout << PythonUtils::GetObjectString(pValue) << std::endl;
    res = callback(pValue);
    //Py_FinalizeEx();

    return res;
}

PyObject* PythonUtils::sysMod = NULL;

PyObject* PythonUtils::GetLastError() {
    PyObject* exception, * v, * tb;
	if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
        return NULL;
	}
	PyErr_Fetch(&exception, &v, &tb);
	if (exception == NULL)
		return NULL;
	PyErr_NormalizeException(&exception, &v, &tb);
	if (tb == NULL) {
		tb = Py_None;
		Py_INCREF(tb);
	}
	PyException_SetTraceback(v, tb);
	if (exception == NULL)
		return NULL;
	/* Now we know v != NULL too */
	/*if (1) {
		if (_PySys_SetObjectId(&PyId_last_type, exception) < 0) {
			PyErr_Clear();
		}
		if (_PySys_SetObjectId(&PyId_last_value, v) < 0) {
			PyErr_Clear();
		}
		if (_PySys_SetObjectId(&PyId_last_traceback, tb) < 0) {
			PyErr_Clear();
		}
	}*/

	Py_XDECREF(exception);
	//Py_XDECREF(v);
	Py_XDECREF(tb);
    return v;
}

std::string PythonUtils::GetObjectString(PyObject* object) {
    if (object == NULL) {
        return "NULL";
    }
    return PyStringToString(PyObject_Repr(object));
}

std::string PythonUtils::GetLastErrorTraceBack() {
    if (PythonUtils::sysMod == NULL) {
        PythonUtils::sysMod = PyImport_ImportModule("sys");
    }
    PyObject* lastTraceBack = PyObject_GetAttrString(PythonUtils::sysMod, "last_traceback");
    PyObject* errorRepr = PyObject_Repr(lastTraceBack);
    std::string res = PyStringToString(errorRepr);
    Py_XDECREF(lastTraceBack);
    Py_XDECREF(errorRepr);
    return res;
}

BOOL PythonUtils::IsTypeOf(PyObject* object, std::string& typeName) {
    if (object == NULL) {
        return FALSE;
    }
    return object->ob_type->tp_name == typeName;
}

PyObject* PyFileInfoModule::OpenFileInfoCache(PyObject* self, PyObject* args) {
    char* path;
    if (!PyArg_ParseTuple(args, "i", &path)) {
        return Py_None;
    }

    FileInfo *file = new FileInfo(path);
    if (file == NULL) {
        return PyErr_NoMemory();
    }
    PyFileInfoModule::fileCache[path] = file;
    return Py_None;
}

PyObject* PyFileInfoModule::CloseFileInfoCache(PyObject* self, PyObject* args) {
    PyFileInfoModule::fileCache.clear();
    return Py_None;
}

PyObject* PyFileInfoModule::GetBasicInfo(PyObject* self, PyObject* args) {
    char* path;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return Py_None;
    }
    PyObject* info;

    FileInfo file(StringUtils::s2ws(path).c_str());
    if (file.SetBasicInfo() != ERROR_SUCCESS) {
        return Py_None;
    }

    info = PyDict_New();
    if (info == NULL) {
        return Py_None;
    }

    
    auto fsi = [&info](const char* key, LONG64 value) {
        PyObject* pyKey = PyUnicode_FromString(key);
        PyObject* pyValue = PyLong_FromLongLong(value);
        PyDict_SetItem(info, pyKey, pyValue);
        Py_XDECREF(pyKey);
        Py_XDECREF(pyValue);
    };

    
    file.pBasicInfo;
    fsi("CreationTime", file.pBasicInfo->CreationTime.QuadPart);
    fsi("LastAccessTime", file.pBasicInfo->LastAccessTime.QuadPart);
    fsi("LastWriteTime", file.pBasicInfo->LastWriteTime.QuadPart);
    fsi("ChangeTime", file.pBasicInfo->ChangeTime.QuadPart);
    PyObject* _pyAttributes = PyList_New(0);
    auto _std_attributes = file.GetAttributes();
    for (auto& _attr : _std_attributes) {
        PyObject* pyAttribute = PyUnicode_FromString(StringUtils::ws2s(_attr).c_str());
        PyList_Append(_pyAttributes, pyAttribute);
        Py_XDECREF(pyAttribute);
    }
    PyObject* _pyKeyString = PyUnicode_FromString("Attributes");
    PyDict_SetItem(info, _pyKeyString, _pyAttributes);
    Py_XDECREF(_pyKeyString);
    Py_XDECREF(_pyAttributes);
    return info;
}

PyObject* PyFileInfoModule::GetStandardInfo(PyObject* self, PyObject* args) {
    char* path = NULL;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return Py_None;
    }
    PyObject* info;
    FileInfo* file = NULL;
    if (path == NULL) {
        return Py_None;
    }
    if (isFileCacheEnable == true) {
        if (fileCache.count(path) > 0) {
            file = fileCache[path];
        }
        else {
            fileCache[path] = new FileInfo(path);
        }
        
    }
    else {
        FileInfo* file = new FileInfo(path);
        if (file == NULL) {
            Py_XDECREF(path);
            return Py_None;
        }
    }
    Py_XDECREF(path);
    if (file->pStandardInfo == NULL) {
        if (file->SetBasicInfo() != ERROR_SUCCESS) {

            return Py_None;
        }
    }

    info = PyDict_New();
    _dict_insert_help(info, PyUnicode_FromString("AllocationSize"), PyLong_FromLongLong(file->pStandardInfo->AllocationSize.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("EndOfFile"), PyLong_FromLongLong(file->pStandardInfo->EndOfFile.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("NumberOfLinks"), PyLong_FromLongLong(file->pStandardInfo->NumberOfLinks));
    _dict_insert_help(info, PyUnicode_FromString("DeletePending"), PyBool_FromLong(file->pStandardInfo->DeletePending));
    _dict_insert_help(info, PyUnicode_FromString("Directory"), PyBool_FromLong(file->pStandardInfo->Directory));
    if (isFileCacheEnable == false) {
        delete file;
    }
    
    return info;
}

PyObject* PyFileInfoModule::GetStatInfo(PyObject* self, PyObject* args) {
    char* path = NULL;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return Py_None;
    }
    PyObject* info;
    FileInfo* file = NULL;
    if (isFileCacheEnable == true) {
        if (fileCache.count(path) > 0) {
            file = fileCache[path];
        }
        else {
            fileCache[path] = new FileInfo(path);
        }
    }
    else {
        FileInfo* file = new FileInfo(path);
        if (file == NULL) {
            Py_XDECREF(path);
            return Py_None;
        }
    }
    Py_XDECREF(path);
    if (file->pStatInfo == NULL) {
        if (file->SetBasicInfo() != ERROR_SUCCESS) {
            return Py_None;
        }
    }

    info = PyDict_New();
    _dict_insert_help(info, PyUnicode_FromString("FileId"), PyLong_FromLongLong(file->pStatInfo->FileId.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("CreationTime"), PyLong_FromLongLong(file->pStatInfo->CreationTime.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("LastAccessTime"), PyLong_FromLongLong(file->pStatInfo->LastAccessTime.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("LastWriteTime"), PyLong_FromLongLong(file->pStatInfo->LastWriteTime.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("ChangeTime"), PyLong_FromLongLong(file->pStatInfo->ChangeTime.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("AllocationSize"), PyLong_FromLongLong(file->pStatInfo->AllocationSize.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("EndOfFile"), PyLong_FromLongLong(file->pStatInfo->EndOfFile.QuadPart));
    _dict_insert_help(info, PyUnicode_FromString("FileAttributes"), PyLong_FromLongLong(file->pStatInfo->FileAttributes));
    _dict_insert_help(info, PyUnicode_FromString("ReparseTag"), PyLong_FromLongLong(file->pStatInfo->ReparseTag));
    _dict_insert_help(info, PyUnicode_FromString("NumberOfLinks"), PyLong_FromLongLong(file->pStatInfo->NumberOfLinks));
    _dict_insert_help(info, PyUnicode_FromString("EffectiveAccess"), PyLong_FromLongLong(file->pStatInfo->EffectiveAccess));

    return info;
}

PyObject* PyFileInfoModule::FileInfoModuleInit() {
    return PyModule_Create(&moduleDef);
}

const static std::thread::id MAIN_THREAD_ID = std::this_thread::get_id();
PythonVM::PythonVM() {
    s_interp = new sub_interpreter();
}

void PythonVM::ExecCode(const char* s) {
    if (std::this_thread::get_id() != MAIN_THREAD_ID) {
        sub_interpreter::thread_scope scope(s_interp->interp());
        PyRun_SimpleString(s);
    }
    else {
        PyRun_SimpleString(s);
    }
}

void PythonVM::RunFunction(PyObjectCallback callback, const char* cstr_file, const char* cstr_function, PyArgs& args) {
    if (std::this_thread::get_id() != MAIN_THREAD_ID) {
        sub_interpreter::thread_scope scope(s_interp->interp());
        PythonUtils::RunFunction(callback, cstr_file, cstr_function, args);
    }
    else {
        PythonUtils::RunFunction(callback, cstr_file, cstr_function, args);
    }
}

PythonVM::~PythonVM() {
    if (s_interp != NULL) {
        delete s_interp;
    }
        
}

PythonVMMgr* PythonVMMgr::_one_instance = NULL;

PyObject* PyRegistryUtilsModule::GetRegistryValue(PyObject* self, PyObject* args) {
    char* path;
    char* key;
    if (!PyArg_ParseTuple(args, "ss", &path,&key)) {
        return Py_None;
    }

    BytesBuffer buffer = RegistryUtils::GetValueStatic(StringUtils::s2ws(path).c_str(), StringUtils::s2ws(key).c_str());
    PyObject* pyBytes = PyByteArray_FromStringAndSize(buffer.c_str(), buffer.size());
    return pyBytes;
}



PyObject* PyRegistryUtilsModule::ListSubKeys(PyObject* self, PyObject* args) {
    char* path;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return Py_None;
    }

    auto _wpath = StringUtils::s2ws(path);
    RegistryUtils utils(_wpath);
    auto subkeys = utils.ListSubKeys();

    PyObject* pyKeys = NULL;
    pyKeys = PyList_New(0);
    for (auto& key : subkeys) {
        _list_insert_help(pyKeys, PyUnicode_FromString(StringUtils::ws2s(key).c_str()));
    }

    return pyKeys;
}

PyObject* PyRegistryUtilsModule::ListValueNames(PyObject* self, PyObject* args) {
    char* path;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return Py_None;
    }

    auto _wpath = StringUtils::s2ws(path);
    PyObject* pyItems = PyList_New(0);
    
    RegistryUtils utils(_wpath);
    auto valueNames = utils.ListValueNames();
    for (auto& name : valueNames) {
        _list_insert_help(pyItems, PyUnicode_FromString(StringUtils::ws2s(name.c_str()).c_str()));
    }

    return pyItems;
}

PyObject* PyRegistryUtilsModule::RegistryModuleInit() {
    return PyModule_Create(&moduleDef);
}

PyObject* PyUtils::ReturnObject(PyObject* self, PyObject* args) {
    PyObject* object;
    if (!PyArg_ParseTuple(args, "o", &object)) {
        return Py_None;
    }

    return Py_None;
}
#include "AccountInfo.h"
PyObject* PyAccountInfoModule::InitAccounts(PyObject* self, PyObject* args) {
    PyObject* pyAccounts = PyList_New(0);
    AccountInfoManager mgr;
    mgr.Initialize();
    auto accountList = mgr.GetAccountList();
    for (auto& account : accountList) {
        PyObject* serialize = PyDict_New();
        PyList_Append(pyAccounts, serialize);
        _dict_insert_help(serialize, PyUnicode_FromString("username"), PyUnicode_FromString(StringUtils::ws2s(account->userName).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("comment"), PyUnicode_FromString(StringUtils::ws2s(account->comment).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("passwordAge"), PyLong_FromUnsignedLong(account->passwordAge));
        _dict_insert_help(serialize, PyUnicode_FromString("privilege"), PyLong_FromUnsignedLong(account->privilege));
        _dict_insert_help(serialize, PyUnicode_FromString("homeDir"), PyUnicode_FromString(StringUtils::ws2s(account->homeDir).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("flags"), PyLong_FromUnsignedLong(account->flags));
        _dict_insert_help(serialize, PyUnicode_FromString("scriptPath"), PyUnicode_FromString(StringUtils::ws2s(account->scriptPath).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("authFlags"), PyLong_FromUnsignedLong(account->authFlags));
        _dict_insert_help(serialize, PyUnicode_FromString("fullName"), PyUnicode_FromString(StringUtils::ws2s(account->fullName).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("usrComment"), PyUnicode_FromString(StringUtils::ws2s(account->usrComment).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("params"), PyUnicode_FromString(StringUtils::ws2s(account->params).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("workstations"), PyUnicode_FromString(StringUtils::ws2s(account->workstations).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("lastLogon"), PyLong_FromUnsignedLong(account->lastLogon));
        _dict_insert_help(serialize, PyUnicode_FromString("lastLogoff"), PyLong_FromUnsignedLong(account->lastLogoff));
        _dict_insert_help(serialize, PyUnicode_FromString("acctExpires"), PyLong_FromUnsignedLong(account->acctExpires));
        _dict_insert_help(serialize, PyUnicode_FromString("maxStorage"), PyLong_FromUnsignedLong(account->maxStorage));
        _dict_insert_help(serialize, PyUnicode_FromString("unitsPerWeek"), PyLong_FromUnsignedLong(account->unitsPerWeek));
        _dict_insert_help(serialize, PyUnicode_FromString("badPasswordCount"), PyLong_FromUnsignedLong(account->badPasswordCount));
        _dict_insert_help(serialize, PyUnicode_FromString("numLogons"), PyLong_FromUnsignedLong(account->numLogons));
        _dict_insert_help(serialize, PyUnicode_FromString("logonServer"), PyUnicode_FromString(StringUtils::ws2s(account->logonServer).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("countryCode"), PyLong_FromUnsignedLong(account->countryCode));
        _dict_insert_help(serialize, PyUnicode_FromString("codePage"), PyLong_FromUnsignedLong(account->codePage));
        _dict_insert_help(serialize, PyUnicode_FromString("userId"), PyLong_FromUnsignedLong(account->userId));
        _dict_insert_help(serialize, PyUnicode_FromString("primaryGroupId"), PyLong_FromUnsignedLong(account->primaryGroupId));
        _dict_insert_help(serialize, PyUnicode_FromString("profile"), PyUnicode_FromString(StringUtils::ws2s(account->profile).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("homeDirDrive"), PyUnicode_FromString(StringUtils::ws2s(account->homeDirDrive).c_str()));
        _dict_insert_help(serialize, PyUnicode_FromString("passwordExpired"), PyLong_FromUnsignedLong(account->passwordExpired));
        PyList_Append(pyAccounts,serialize);
        Py_XDECREF(serialize);
    }
    return pyAccounts;
}

PyObject* PyAccountInfoModule::AccountInfoModuleInit() {
    return PyModule_Create(&moduleDef);
}
