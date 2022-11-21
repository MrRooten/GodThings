#pragma once
#include "public.h"
#include <string>
#include "PythonUtils.h"
#include "threadpool/thread_pool.h"
class ProcHandler {
private:
	std::string message;
	std::string result;
public:
	ProcHandler(std::string &Message);
	DWORD Process();
	std::string GetResult();

};
VOID Serve();
class ProcServer {
private:
	int maxConnection;
	LPCSTR _pipeName = "\\\\.\\pipe\\gtpipe";
	const int BufferSize = 10240;
public:
	static ProcServer* GetServer(int maxConnection);
	ProcServer(int maxConnection);
	BOOL Initialize();
	VOID Serve();
	~ProcServer();
};


