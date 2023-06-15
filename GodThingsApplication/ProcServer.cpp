#include <json/json.h>
#include "ProcServer.h"
#include "utils.h"
#include "Module.h"
#include "PythonUtils.h"
const int BufferSize = 10240;

ProcServer* ProcServer::GetServer(int maxConnection) {
	ProcServer* server = new ProcServer(maxConnection);
	if (server == NULL) {
		return NULL;
	}
	if (!server->Initialize()) {
		return NULL;
	}
	return server;
}

ProcServer::ProcServer(int maxConnection) {
	this->maxConnection = maxConnection;
}

BOOL ProcServer::Initialize() {
	/*this->pool = new ThreadPool(this->maxConnection);
	if (this->pool == NULL) {
		return FALSE;
	}*/
	return TRUE;
}


DWORD WINAPI InstanceThread(LPVOID lpvParam, PyInterpreterState* state);
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD);
std::mutex handle_lock;
DWORD WINAPI InstanceThread(LPVOID lpvParam) {
    CHAR* pchRequest = (CHAR*)LocalAlloc(GPTR, BufferSize);
    CHAR* pchReply = (CHAR*)LocalAlloc(GPTR, BufferSize);

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;

    if (lpvParam == NULL)
    {
        LOG_DEBUG_REASON(L"ERROR - Pipe Server Failure:");
        LOG_DEBUG_REASON(L"InstanceThread got an unexpected NULL value in lpvParam.");
        LOG_DEBUG_REASON(L"InstanceThread exitting.");
        if (pchReply != NULL) LocalFree(pchReply);
        if (pchRequest != NULL) LocalFree(pchRequest);
        return (DWORD)-1;
    }

    if (pchRequest == NULL)
    {
        LOG_DEBUG_REASON(L"ERROR - Pipe Server Failure:");
        LOG_DEBUG_REASON(L"InstanceThread got an unexpected NULL heap allocation.");
        LOG_DEBUG_REASON(L"InstanceThread exitting.");
        if (pchReply != NULL) LocalFree(pchReply);
        return (DWORD)-1;
    }

    if (pchReply == NULL)
    {
        LOG_DEBUG_REASON(L"ERROR - Pipe Server Failure:");
        LOG_DEBUG_REASON(L"InstanceThread got an unexpected NULL heap allocation.");
        LOG_DEBUG_REASON(L"InstanceThread exitting.");
        if (pchRequest != NULL) LocalFree(pchRequest);
        return (DWORD)-1;
    }

    LOG_DEBUG_REASON(L"InstanceThread created, receiving and processing messages.");


    hPipe = (HANDLE)lpvParam;

    while (1) {
        
        fSuccess = ReadFile(
            hPipe,        // handle to pipe 
            pchRequest,    // buffer to receive data 
            BufferSize, // size of buffer 
            &cbBytesRead, // number of bytes read 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbBytesRead == 0) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                LOG_DEBUG_REASON(L"InstanceThread: client disconnected.\n");
            }
            else {
                LOG_DEBUG_REASON(L"InstanceThread ReadFile failed");
            }
            break;
        }

        std::string s(pchRequest, cbBytesRead + 1);
        ProcHandler handler(s);
        handler.Process();
        auto result = handler.GetResult();

        fSuccess = WriteFile(
            hPipe,        // handle to pipe 
            result.c_str(),     // buffer to write from 
            static_cast<DWORD>(result.size()), // number of bytes to write 
            &cbWritten,   // number of bytes written 
            0);        // not overlapped I/O 
        printf("Write Size:%d\n", cbWritten);
        if (!fSuccess || cbReplyBytes != cbWritten)
        {
            LOG_DEBUG_REASON(L"InstanceThread WriteFile failed");
            break;
        }
        break;
        SetLastError(0);
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    LocalFree(pchRequest);
    LocalFree(pchReply);
    return 1;
}
#include <strsafe.h>
#include <queue>

VOID Serve() {
#ifdef PYTHON_ENABLE
    initialize init;
#endif // PYTHON_ENABLE
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    LPCSTR _pipeName = "\\\\.\\pipe\\gtpipe";
    const SIZE_T BufferSize = 10240;
    ModuleMgr::GetMgr();
#ifdef PYTHON_ENABLE
    sub_interpreter s1;
    sub_interpreter ss[20];
    std::thread t4{ [](PyInterpreterState* interp) {
        sub_interpreter::thread_scope scope(interp);
        ModuleMgr::GetMgr();
} , sub_interpreter::current() };
    enable_threads_scope t;
#endif
    int i = 0;
    for (;;) {
        HANDLE _hPipe = CreateNamedPipe(
            _pipeName,           
            PIPE_ACCESS_DUPLEX,     
            PIPE_TYPE_MESSAGE |       
            PIPE_READMODE_MESSAGE | 
            PIPE_WAIT,              
            PIPE_UNLIMITED_INSTANCES, 
            BufferSize,            
            BufferSize,            
            0,                      
            NULL);              

        if (_hPipe == NULL) {
            break;
        }

        fConnected = ConnectNamedPipe(_hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (fConnected)
        {
            i++;
            printf("Client connected, creating a processing thread.");
            //PythonVM* vm = new PythonVM();

            std::thread t1([_hPipe]() {
                InstanceThread((LPVOID)_hPipe);
              
                });
            //_f.wait();
            //printf("Wait\n");
            t1.detach();


            // Create a thread for this client. 

        }
        else
            // The client could not connect, so close the pipe. 
            CloseHandle(_hPipe);


    }
}



ProcHandler::ProcHandler(std::string &Message) {
    this->message = Message;
    //printf("%s\n",Message.c_str());
}
#include <mutex>
std::mutex locker;
DWORD ProcHandler::Process() {
    Json::Reader reader;
    Json::Value root;
    std::cout << "Client Message:" << this->message << std::endl;
    if (!reader.parse(this->message, root)) {
        this->message = reader.getFormattedErrorMessages();
        return -1;
    }

    const char* _command = root["command"].asCString();
    std::string_view command = _command;
    Json::Value result;
    do {
        if (command == "list_modules") {
            auto Mgr = ModuleMgr::GetMgr();
            size_t len = Mgr->modules.size();
            int result_i = 0;
            for (int i = 0; i < len; i++) {
                //if (Mgr->modules[i]->Type == L"LastMode") {
                //    continue;
                //}
                if (Mgr->modules[i]->RunType != ModuleAuto) {
                    continue;
                }
                result["list_modules"][result_i] = Mgr->modules[i]->GetModuleMetaJson();
                result_i += 1;
            }
        }
        else if (command == "run_module") {
            auto Mgr = ModuleMgr::GetMgr();
            if (!root["module"].isString()) {
                result["error"] = "Must designate the module as string";
            }

            const char* modName = root["module"].asCString();
            Module* mod = Mgr->FindModuleByName(modName);
            if (mod == NULL) {
                result["error"] = "Not found module";
                break;
            }
            Module::Args args;
            if (!root["args"].isNull()) {
                auto &_json_args = root["args"];
                if (_json_args.isArray()) {
                    for (Json::Value::ArrayIndex i = 0; i < _json_args.size(); i++) {
                        args[std::to_string(i)] = _json_args[i].asString();
                    }
                }
                else if (_json_args.isObject()) {
                    for (auto iter = _json_args.begin(); iter != _json_args.end(); iter++) {
                        args[iter.key().asString()] = (*iter).asCString();
                    }
                }
                else if (_json_args.isString()) {
                    args["0"] = _json_args.asString();
                }
                else {
                    result["error"] = "Not support parameter type";
                    break;
                }
            }
            mod->SetArgs(args);
#ifdef PYTHON_ENABLE
            mod->SetVM(state);
#endif // PYTHON_ENABLE
            ResultSet* _result_set = NULL;
            _result_set = mod->ModuleRun();
            result["module_result"] = _result_set->ToJsonObject();
            delete _result_set;
            
            /*enable_threads_scope* scope = NULL;
            bool is_lock = false;
            if (locker.try_lock()) {
                is_lock = true;
                scope = new enable_threads_scope;
                
            }
            
            t.join();
            delete _result_set;
            if (scope != NULL)
                delete scope;
            if (is_lock) {
                locker.unlock();
            }*/
        }
        else {
            result["error"] = "Unknown command";
        }
    } while (0);
    
    Json::FastWriter writer;
    this->result = writer.write(result);
    return 0;
}

std::string ProcHandler::GetResult() {
    return this->result;
}
