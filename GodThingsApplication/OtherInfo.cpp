#include "OtherInfo.h"

SchduleTaskMgr* SchduleTaskMgr::_single = NULL;
SchduleTaskMgr* SchduleTaskMgr::GetMgr() {
    if (SchduleTaskMgr::_single == NULL) {
        try {
            SchduleTaskMgr::_single = new SchduleTaskMgr();
        }
        catch (...) {
            delete SchduleTaskMgr::_single;
            SchduleTaskMgr::_single = NULL;
        }
    }

    return SchduleTaskMgr::_single;
}

SchduleTaskMgr::SchduleTaskMgr() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    if (FAILED(hr)) {
        throw std::exception();
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr)) {
        CoUninitialize();
        throw std::exception();
    }

    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);

    if (FAILED(hr)) {
        CoUninitialize();
        throw std::exception();
    }

    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        throw std::exception();
    }

    this->pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

    pService->Release();
    if (FAILED(hr)) {
        CoUninitialize();
        throw std::exception();
    }



}

SchduleTask& SchduleTaskMgr::NextTask() {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    HRESULT hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
    LONG count = 0;
    pTaskCollection->get_Count(&count);
    TASK_STATE taskState;
    for (LONG i = 0; i < count; i++) {
        IRegisteredTask* pRegisteredTask = NULL;
        hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

        if (SUCCEEDED(hr))
        {
            BSTR taskName = NULL;
            hr = pRegisteredTask->get_Name(&taskName);
            if (SUCCEEDED(hr))
            {
                printf("\nTask Name: %S", taskName);
                SysFreeString(taskName);

                hr = pRegisteredTask->get_State(&taskState);
                if (SUCCEEDED(hr))
                    printf("\n\tState: %d", taskState);
                else
                    printf("\n\tCannot get the registered task state: %x", hr);
            }
            else
            {
                printf("\nCannot get the registered task name: %x", hr);
            }
            pRegisteredTask->Release();
        }
        else
        {
            printf("\nCannot get the registered task item at index=%d: %x", i + 1, hr);
        }
    }

}

static void _get_tasks_helper(std::vector<SchduleTask>& save,ITaskFolder* folder) {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    HRESULT hr = folder->GetTasks(NULL, &pTaskCollection);
    LONG count = 0;
    pTaskCollection->get_Count(&count);
    ITaskFolderCollection* collection;
    for (LONG i = 0; i < count; i++) {
        IRegisteredTask* pRegisteredTask = NULL;
        hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

        if (SUCCEEDED(hr)) {
            save.push_back(pRegisteredTask);
            pRegisteredTask->Release();
        }
        else {
            continue;
        }
    }
    folder->GetFolders(0, &collection);
    collection->get_Count(&count);
    if (count != 0) {
        for (int i = 0; i < count; i++) {
            ITaskFolder* cur;
            hr = collection->get_Item(_variant_t(i+1), &cur);
            if (FAILED(hr)) {
                continue;
            }
            _get_tasks_helper(save, cur);
            cur->Release();
        }
    }
    collection->Release();
}

static void _get_tasks_helper2(std::function<void(SchduleTask&)> callback, ITaskFolder* folder) {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    HRESULT hr = folder->GetTasks(NULL, &pTaskCollection);
    LONG count = 0;
    pTaskCollection->get_Count(&count);
    ITaskFolderCollection* collection;
    for (LONG i = 0; i < count; i++) {
        IRegisteredTask* pRegisteredTask = NULL;
        hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

        if (SUCCEEDED(hr)) {
            SchduleTask task(pRegisteredTask);
            callback(task);
            pRegisteredTask->Release();
        }
        else {
            continue;
        }
    }
    folder->GetFolders(0, &collection);
    collection->get_Count(&count);
    if (count != 0) {
        for (int i = 0; i < count; i++) {
            ITaskFolder* cur;
            hr = collection->get_Item(_variant_t(i + 1), &cur);
            if (FAILED(hr)) {
                continue;
            }
            _get_tasks_helper2(callback, cur);
            cur->Release();
        }
    }
    collection->Release();
}
std::vector<SchduleTask> SchduleTaskMgr::GetTasks() {
    std::vector<SchduleTask> result;
    IRegisteredTaskCollection* pTaskCollection = NULL;
    HRESULT hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
    LONG count = 0;
    pTaskCollection->get_Count(&count);
    TASK_STATE taskState;
    _get_tasks_helper(result, this->pRootFolder);
    return result;
}

void SchduleTaskMgr::EnumTasks(std::function<void(SchduleTask*)> callback) {

}

SchduleTaskMgr::~SchduleTaskMgr() {
    CoUninitialize();
}

SchduleTask::SchduleTask(IRegisteredTask* task) {
    HRESULT hr;
    BSTR p;
    hr = task->get_Path(&p);
    if (FAILED(hr)) {
        return;
    }
    this->path = p;


    hr = task->get_Name(&p);
    if (FAILED(hr)) {
        return;
    }
    this->name = p;


    hr = task->GetRunTimes(&this->start_time, &this->end_time, &this->count, &this->run_times);
    if (FAILED(hr)) {
        return;
    }
    
    hr = task->get_State(&this->taskState);
    if (FAILED(hr)) {
        return;
    }

    this->_task = task;
}

std::wstring& SchduleTask::getPath() {
    return this->path;
}

std::wstring& SchduleTask::getName() {
    return this->name;
}




