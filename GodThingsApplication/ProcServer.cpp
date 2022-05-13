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
DWORD WINAPI InstanceThread(LPVOID lpvParam, PyInterpreterState* state)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
    CHAR* pchRequest = (CHAR*)LocalAlloc(GPTR, BufferSize);
    CHAR* pchReply = (CHAR*)LocalAlloc(GPTR, BufferSize);

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;

    // Do some extra error checking since the app will keep running even if this
    // thread fails.

    if (lpvParam == NULL)
    {
        Logln(DEBUG_LEVEL,L"\nERROR - Pipe Server Failure:\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread got an unexpected NULL value in lpvParam.\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread exitting.\n");
        if (pchReply != NULL) LocalFree(pchReply);
        if (pchRequest != NULL) LocalFree(pchRequest);
        return (DWORD)-1;
    }

    if (pchRequest == NULL)
    {
        Logln(DEBUG_LEVEL, L"\nERROR - Pipe Server Failure:\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread got an unexpected NULL heap allocation.\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread exitting.\n");
        if (pchReply != NULL) LocalFree(pchReply);
        return (DWORD)-1;
    }

    if (pchReply == NULL)
    {
        Logln(DEBUG_LEVEL, L"\nERROR - Pipe Server Failure:\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread got an unexpected NULL heap allocation.\n");
        Logln(DEBUG_LEVEL, L"   InstanceThread exitting.\n");
        if (pchRequest != NULL) LocalFree(pchRequest);
        return (DWORD)-1;
    }

    // Print verbose messages. In production code, this should be for debugging only.
    Logln(DEBUG_LEVEL, L"InstanceThread created, receiving and processing messages.\n");

    // The thread's parameter is a handle to a pipe object instance. 

    hPipe = (HANDLE)lpvParam;

    // Loop until done reading
    while (1)
    {
        
        // Read client requests from the pipe. This simplistic code only allows messages
        // up to BUFSIZE characters in length.
        fSuccess = ReadFile(
            hPipe,        // handle to pipe 
            pchRequest,    // buffer to receive data 
            BufferSize, // size of buffer 
            &cbBytesRead, // number of bytes read 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbBytesRead == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                Logln(DEBUG_LEVEL, L"InstanceThread: client disconnected.\n");
            }
            else
            {
                Logln(DEBUG_LEVEL, L"InstanceThread ReadFile failed, GLE=%d,%s.\n", GetLastError(),GetLastErrorAsStringThreadSafe().c_str());
            }
            break;
        }

        // Process the incoming message.
        //GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);
        std::string s(pchRequest, cbBytesRead + 1);
        ProcHandler handler(s);
        handler.Process(state);
        auto result = handler.GetResult();
        // Write the reply to the pipe. 
        fSuccess = WriteFile(
            hPipe,        // handle to pipe 
            result.c_str(),     // buffer to write from 
            result.size(), // number of bytes to write 
            &cbWritten,   // number of bytes written 
            NULL);        // not overlapped I/O 
        printf("Write Size:%d\n", cbWritten);
        if (!fSuccess || cbReplyBytes != cbWritten)
        {
            Logln(DEBUG_LEVEL, L"InstanceThread WriteFile failed, GLE=%d,%s.\n", GetLastError(), GetLastErrorAsStringThreadSafe().c_str());
            break;
        }
        break;
        SetLastError(0);
    }

    // Flush the pipe to allow the client to read the pipe's contents 
    // before disconnecting. Then disconnect the pipe, and close the 
    // handle to this pipe instance. 
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    LocalFree(pchRequest);
    LocalFree(pchReply);
    return 1;
}
#include <strsafe.h>
#include <queue>
struct sub_interpreter_manager {
    std::queue<sub_interpreter*> ss;
    sub_interpreter_manager() {
        for (int i = 0; i < 20; i++) {
            ss.push(new sub_interpreter());
        }
    }

    sub_interpreter* get() {
        auto res = ss.front();
        ss.pop();
        ss.push(res);
        return res;
    }

    ~sub_interpreter_manager() {
        while (ss.size() > 0) {
            auto s = ss.front();
            delete s;
            ss.pop();
        }
    }
};


VOID Serve() {
    initialize init;
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hThread;
    LPCSTR _pipeName = "\\\\.\\pipe\\gtpipe";
    const SIZE_T BufferSize = 10240;
    sub_interpreter s1;
    sub_interpreter ss[20];
    std::thread t4{ [](PyInterpreterState* interp) {
        sub_interpreter::thread_scope scope(interp);
        ModuleMgr::GetMgr();
} , sub_interpreter::current() };
    enable_threads_scope t;
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
            printf("Client connected, creating a processing thread.\n");
            //PythonVM* vm = new PythonVM();
            
            std::thread t1([_hPipe](PyInterpreterState* state) {
                sub_interpreter::thread_scope scope(state);
                InstanceThread((LPVOID)_hPipe, state);
              
                }, s1.interp());
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

VOID ProcServer::Serve() {
    ModuleMgr::GetMgr();
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hThread;
    sub_interpreter* s1 = new sub_interpreter();
	for (;;) {
        HANDLE _hPipe = CreateNamedPipe(
			this->_pipeName,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			this->BufferSize,                  // output buffer size 
			this->BufferSize,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (_hPipe == NULL) {
			break;
		}

		fConnected = ConnectNamedPipe(_hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (fConnected)
        {
            printf("Client connected, creating a processing thread.\n");
            //PythonVM* vm = new PythonVM();
            
            
            std::thread t1([_hPipe](PyInterpreterState* state) {
                InstanceThread((LPVOID)_hPipe,state);

                },s1->interp());
            //_f.wait();
            //printf("Wait\n");
            //enable_threads_scope t;
            t1.detach();
            
            // Create a thread for this client. 
            
        }
        else
            // The client could not connect, so close the pipe. 
            CloseHandle(_hPipe);
        
        
	}
}

ProcServer::~ProcServer() {
	//if (this->_hPipe != NULL) {
	//	CloseHandle(this->_hPipe);
	//}
}

ProcHandler::ProcHandler(std::string &Message) {
    this->message = Message;
    //printf("%s\n",Message.c_str());
}
#include <mutex>
std::mutex locker;
DWORD ProcHandler::Process(PyInterpreterState* state) {
    Json::Reader reader;
    Json::Value root;
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
            for (int i = 0; i < len; i++) {
                result["list_modules"][i] = Mgr->modules[i]->GetModuleMetaJson();
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
            mod->SetVM(state);
            ResultSet* _result_set = NULL;
            _result_set = mod->ModuleRun();
            result["module_result"] = _result_set->ToJsonObject();
                
            
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
