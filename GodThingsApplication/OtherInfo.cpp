#include "OtherInfo.h"
#include "tinyxml2.h"
SchduleTaskMgr* SchduleTaskMgr::_single = NULL;
SchduleTaskMgr* SchduleTaskMgr::GetMgr() {
    if (SchduleTaskMgr::_single == NULL) {
        try {
            SchduleTaskMgr::_single = new SchduleTaskMgr();
        }
        catch (...) {
            //delete SchduleTaskMgr::_single;
            SchduleTaskMgr::_single = NULL;
        }
    }

    return SchduleTaskMgr::_single;
}

void SchduleTaskMgr::DeleteMgr() {
    delete SchduleTaskMgr::_single;
    SchduleTaskMgr::_single = NULL;
}

SchduleTaskMgr::SchduleTaskMgr() {
    HRESULT hr = NULL; // = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;

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

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        throw std::exception();
    }

    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);

    if (FAILED(hr)) {
        throw std::exception();
    }

    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        throw std::exception();
    }

    this->pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

    pService->Release();
    if (FAILED(hr)) {
        throw std::exception();
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
            save.push_back(SchduleTask(pRegisteredTask));
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
    //TASK_STATE taskState;
    _get_tasks_helper(result, this->pRootFolder);

    return result;
}

void SchduleTaskMgr::EnumTasks(std::function<void(SchduleTask*)> callback) {

}
#include "StringUtils.h"




SchduleTaskMgr::~SchduleTaskMgr() {
    if (this->pRootFolder != NULL) {
        this->pRootFolder->Release();
    }

}

tinyxml2::XMLElement* findChild(tinyxml2::XMLElement* element, const char* name) {
    auto first = element->FirstChildElement();
    while (first != NULL) {
        auto e_name = first->Name();
        if (_strcmpi(name, e_name) == 0) {
            break;
        }
        first = first->NextSiblingElement();
    }

    return first;
}

TaskInfo::TaskInfo(const wchar_t* xml) {
    tinyxml2::XMLDocument doc;
    doc.Parse(StringUtils::ws2s(xml).c_str());
    auto root = doc.RootElement();
    auto first = root->FirstChildElement();
    auto next = first;
    while (next != NULL) {
        auto name = next->Name();
        if (_strcmpi("RegistrationInfo", name) == 0) {
            auto date = findChild(next, "Date");
            if (date != NULL) {
                this->Date = StringUtils::s2ws(date->GetText());
            }
            auto author = findChild(next, "Author");
            if (author != NULL) {
                this->Author = StringUtils::s2ws(author->GetText());
            }
            auto uri = findChild(next, "Uri");
            if (uri != NULL) {
                this->Uri = StringUtils::s2ws(uri->GetText());
            }
        }
        else if (_strcmpi("Actions", name) == 0) {
            auto exec = next->FirstChildElement();
            if (_strcmpi(exec->Name(), "Exec") == 0) {
                auto command = exec->FirstChildElement();
                auto arguments = command->NextSiblingElement();
                if (arguments == NULL) {
                    this->Exec = StringUtils::s2ws(command->GetText());
                }
                else {
                    this->Exec = StringUtils::s2ws(command->GetText()) + L" " + StringUtils::s2ws(arguments->GetText());
                }
            }
            else if (_strcmpi(exec->Name(), "ComHandler") == 0) {
                auto command = exec->FirstChildElement();
                auto arguments = command->NextSiblingElement();
                if (arguments == NULL) {
                    this->Exec = L"Com:" + StringUtils::s2ws(command->GetText());
                }
                else {
                    this->Exec = L"Com:" + StringUtils::s2ws(command->GetText()) + L" " + StringUtils::s2ws(arguments->GetText());
                }
            }
        }
        else if (_strcmpi("Principals", name) == 0) {
            auto first = next->FirstChildElement();
            while (first != NULL) {
                auto userId = findChild(first, "UserId");
                Principal p;
                if (userId != NULL) {
                    p.SetUserId(StringUtils::s2ws(userId->GetText()));
                }
                auto logonType = findChild(first, "LogonType");
                if (logonType != NULL) {
                    p.SetLogonType(StringUtils::s2ws(logonType->GetText()));
                }

                auto runLevel = findChild(first, "RunLevel");
                if (runLevel != NULL) {
                    p.SetRunLevel(StringUtils::s2ws(runLevel->GetText()));
                }
                first = first->NextSiblingElement();
            }
        }
        next = next->NextSiblingElement();
    }
    return;
}

GTWString& TaskInfo::GetExec() {
    return this->Exec;
}

GTWString& TaskInfo::GetDate() {
    return this->Date;
}

TaskInfo::TaskInfo()
{
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


    //hr = task->GetRunTimes(&this->start_time, &this->end_time, &this->count, &this->run_times);
    if (FAILED(hr)) {
        return;
    }
    
    hr = task->get_State(&this->taskState);
    if (FAILED(hr)) {
        return;
    }
    ITaskDefinition* def;
    task->get_Definition(&def);
    BSTR xml;
    def->get_XmlText(&xml);
    this->info = TaskInfo(xml);
    //def->Release();
}

std::wstring& SchduleTask::getPath() {
    return this->path;
}

std::wstring& SchduleTask::getName() {
    return this->name;
}

GTTime SchduleTask::GetStartTime() {
    return GTTime(this->start_time);
}

GTTime SchduleTask::GetEndTime() {
    return GTTime(this->end_time);
}

std::wstring SchduleTask::GetState() {
    if (this->taskState == TASK_STATE_UNKNOWN) {
        return L"TASK_STATE_UNKNOWN";
    }

    if (this->taskState == TASK_STATE_DISABLED) {
        return L"TASK_STATE_DISABLED";
    }

    if (this->taskState == TASK_STATE_QUEUED) {
        return L"TASK_STATE_QUEUED";
    }

    if (this->taskState == TASK_STATE_READY) {
        return L"TASK_STATE_READY";
    }

    if (this->taskState == TASK_STATE_RUNNING) {
        return L"TASK_STATE_RUNNING";
    }

    return L"TASK_STATE_UNKNOWN";
}

GTWString& SchduleTask::GetExec() {
    return this->info.GetExec();
}

GTWString& SchduleTask::GetRegDate() {
    return this->info.GetDate();
}

SchduleTask::~SchduleTask() {
    //if (this->info != NULL) {
    //    delete this->info;
    //}
}

SecurityProvider::SecurityProvider(SecPkgInfoW& package) {
    this->name = package.Name;
    this->comment = package.Comment;
    this->maxToken = package.cbMaxToken;
    this->RPCID = package.wRPCID;
    this->fCapabilities = package.fCapabilities;
    this->wVersion = package.wVersion;
}

std::vector<SecurityProvider> SecurityProvider::ListProviders() {
    ULONG packageCount = 0;
    PSecPkgInfoW packages;
    std::vector<SecurityProvider> result;
    auto status = EnumerateSecurityPackagesW(&packageCount, &packages);
    if (status == SEC_E_OK) {
        for (int i = 0; i < packageCount; i++) {
            SecurityProvider p(packages[i]);
            result.push_back(p);
        }
    }
    return result;
}

GTWString& SecurityProvider::GetName() {
    return this->name;
}

GTWString& SecurityProvider::GetComment() {
    return this->comment;
}

void Principal::SetUserId(GTWString userId) {
    this->userId = userId;
}

GTWString& Principal::GetUserId() {
    return this->userId;
}

void Principal::SetLogonType(GTWString logonType) {
    this->logonType = logonType;
}

GTWString& Principal::GetLogonType() {
    return this->logonType;
}

void Principal::SetRunLevel(GTWString runLevel) {
    this->runLevel = runLevel;
}

GTWString& Principal::GetRunLevel() {
    return this->runLevel;
}

Principal::Principal()
{
}
