#pragma once
#ifndef _PYTHON_UTILS_H
#define _PYTHON_UTILS_H


#include "public.h"
//#ifdef _WIN64
#include "Python/Python.h"
//#elif _WIN32
//#include "Python310/Python.h"
//#endif
#include <string>
#include "Process.h"
#include <functional>

#ifdef _WIN64
#pragma comment(lib,"PythonLibs\\amd64\\python37.lib")
#elif _WIN32
#pragma comment(lib,"PythonLibs\\win32\\python37.lib")
#endif
namespace PyProcessInfoModule {
	static PyObject module;
	
	static ProcessManager* mgr = NULL;
	PyObject* GetPids(PyObject* self, PyObject* args);

	PyObject* GetProcessName(PyObject* self, PyObject* args);

	PyObject* GetProcessSecurityState(PyObject* self, PyObject* args);

	PyObject* GetProcessMemoryState(PyObject* self, PyObject* args);

	PyObject* GetProcessIOState(PyObject* self, PyObject* args);

	PyObject* GetProcessCPUState(PyObject* self, PyObject* args);

	PyObject* GetProcessHandleState(PyObject* self, PyObject* args);

	//PyObject* GetProcessImageState(PyObject* self, PyObject* args);

	static PyMethodDef methods[] = {
		{"get_pids",GetPids,METH_NOARGS,"Return the PROCESSES received by the process."},
		{"get_process_name",GetProcessName,METH_VARARGS,"Return the process name"},
		{"get_process_security_state",GetProcessSecurityState,METH_VARARGS,"Return the process security state"},
		{"get_process_memory_state",GetProcessMemoryState,METH_VARARGS,"Return the process memory state"},
		{"get_process_io_state",GetProcessIOState,METH_VARARGS,"Return the process io state"},
		{"get_process_cpu_state",GetProcessCPUState,METH_VARARGS,"Return the process cpu state"},
		{"get_process_handle_state",GetProcessHandleState,METH_VARARGS,"Return the process"},
		{NULL,NULL,0,0}
	};
	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"process_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};
	PyObject* ProcessInfoModuleInit();
};

namespace PySystemInfoModule {
	PyObject* GetSystemBasicInfo(PyObject* self, PyObject* args);

	PyObject* GetProcessorInfo(PyObject* self, PyObject* args);

	PyObject* GetPerfInfo(PyObject* self, PyObject* args);

	//PyObject* GetNtGlobalFlag(PyObject* self, PyObject* args);

	static PyMethodDef methods[] = {
		{"get_basic_info",GetSystemBasicInfo,METH_NOARGS,"Return the basic info of system"},
		{"get_processor_info",GetProcessorInfo,METH_NOARGS,"Return the info of processor"},
		{"get_performance_info",GetPerfInfo,METH_NOARGS,"Return the performance info"},
		{NULL,NULL,NULL,NULL}
		//{"get_nt_global_flag",GetNtGlobalFlag,METH_NOARGS,"Return the NtGlobalFlag"}
	};

	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"system_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};

	PyObject* SystemInfoModuleInit();
};

namespace PyRegistryUtilsModule {
	PyObject* GetRegistryValue(PyObject* self, PyObject* args);

	PyObject* ListSubKeys(PyObject* self, PyObject* args);

	PyObject* ListValueNames(PyObject* self, PyObject* args);

	static PyMethodDef methods[] = {
		{"get_value",GetRegistryValue,METH_VARARGS,"Return the registry value"},
		{"list_subkeys",ListSubKeys,METH_VARARGS,"List the registry path's subkeys"},
		{"list_names",ListValueNames,METH_VARARGS,"List the path's items"},
		{NULL,NULL,0,0}
	};
	
	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"registry_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};
	PyObject* RegistryModuleInit();
};

namespace PyServiceModule {

};

namespace PyEventLogModule {

};


namespace PyFileInfoModule {
	using FileCache = std::map<std::string, FileInfo*>;
	static FileCache fileCache;
	static bool isFileCacheEnable = false;
	PyObject* OpenFileInfoCache(PyObject* self, PyObject* args);

	PyObject* CloseFileInfoCache(PyObject* self, PyObject* args);

	PyObject* GetBasicInfo(PyObject* self, PyObject* args);

	PyObject* GetStandardInfo(PyObject* self, PyObject* args);

	PyObject* GetStatInfo(PyObject* self, PyObject* args);

	//PyObject* GetCaseSensitiveInfo(PyObject* self, PyObject* args);

	//PyObject* GetIoPriorityHintInfo(PyObject* self, PyObject* args);

	//PyObject* GetLinksInfo(PyObject* self, PyObject* args);

	static PyMethodDef methods[] = {
		{"open_fileinfo_cache",OpenFileInfoCache,METH_NOARGS,"Open fileinfo cache to cache fileinfo"},
		{"close_fileinfo_cache",CloseFileInfoCache,METH_NOARGS,"Close fileinfo cache"},
		{"get_basic_info",GetBasicInfo,METH_VARARGS,"Return the basic info of file"},
		{"get_standard_info",GetStandardInfo,METH_VARARGS,"Return the standard info of file"},
		{"get_stat_info",GetStatInfo,METH_VARARGS,"Return the stat info of file"},
		{NULL,NULL,0,0}
	//	//{"get_nt_global_flag",GetNtGlobalFlag,METH_NOARGS,"Return the NtGlobalFlag"}
	};

	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"file_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};

	PyObject* FileInfoModuleInit();
};

namespace PyUtils {
	PyObject* ReturnObject(PyObject* self, PyObject* args);

	static PyMethodDef methods[] = {
		{"return_object",ReturnObject,METH_VARARGS,"Return Object"},
		{NULL,NULL,0,0}
	};
};

namespace PyAccountInfoModule {
	PyObject* InitAccounts(PyObject* self, PyObject* args);
	static PyMethodDef methods[] = {
		{"list_usernames",InitAccounts,METH_NOARGS,"List System Usernames"},
		{NULL,NULL,0,0}
		//	//{"get_nt_global_flag",GetNtGlobalFlag,METH_NOARGS,"Return the NtGlobalFlag"}
	};
	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"account_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};
	PyObject* AccountInfoModuleInit();
};

namespace PyNetworkInfoModule {

};

namespace PyServiecInfoModule {
	PyObject* InitServices(PyObject* self, PyObject* args);
	static PyMethodDef methods[] = {
		{NULL,NULL,0,0}
	};
	static PyModuleDef moduleDef = {
		PyModuleDef_HEAD_INIT,
		"service_internal",
		NULL,
		-1,
		methods,
		NULL,
		NULL,
		NULL,
		NULL
	};
}
using PyTypes = std::map<std::string, PyTypeObject*>;
using PyObjectCallback = std::function<int(LPVOID)>;
using PyArgs = std::vector<PyObject*>;
class PythonUtils {
public:
	static PyObject* sysMod;
	static bool isInitialize;
	static bool Initialize();
	static bool Finalize();
	static DWORD ExecString(const char* pyString);
	static DWORD LoadFile(const char* pyFile);
	static DWORD RunFunction(PyObjectCallback, const char* file, const char* function, PyArgs &args);
	static PyObject* GetLastError();
	static std::string GetObjectString(PyObject* object);
	static std::string GetLastErrorTraceBack();
	static inline std::string GetObjectTypeName(PyObject* object) {
		return object == NULL ? NULL : object->ob_type->tp_name;
	}
	static BOOL IsTypeOf(PyObject* object, std::string& typeName);
	static char* PyStringToString(PyObject* object);
	static std::string GetLastErrorAsString();
};

// initialize and clean up python
struct initialize
{
	initialize()
	{
		PyImport_AppendInittab("file_internal", &PyFileInfoModule::FileInfoModuleInit);
		PyImport_AppendInittab("process_internal", &PyProcessInfoModule::ProcessInfoModuleInit);
		PyImport_AppendInittab("system_internal", &PySystemInfoModule::SystemInfoModuleInit);
		PyImport_AppendInittab("registry_internal", &PyRegistryUtilsModule::RegistryModuleInit);
		PyImport_AppendInittab("account_internal", &PyAccountInfoModule::AccountInfoModuleInit);
		Py_InitializeEx(1);
		//PyEval_InitThreads(); // not needed as of Python 3.7, deprecated as of 3.9
	}

	~initialize()
	{
		Py_Finalize();
	}
};

// allow other threads to run
class enable_threads_scope
{
public:
	enable_threads_scope()
	{
		_state = PyEval_SaveThread();
	}

	~enable_threads_scope()
	{
		PyEval_RestoreThread(_state);
	}

private:

	PyThreadState* _state;
};

// restore the thread state when the object goes out of scope
class restore_tstate_scope
{
public:

	restore_tstate_scope()
	{
		_ts = PyThreadState_Get();
	}

	~restore_tstate_scope()
	{
		PyThreadState_Swap(_ts);
	}

private:

	PyThreadState* _ts;
};

// swap the current thread state with ts, restore when the object goes out of scope
class swap_tstate_scope
{
public:

	swap_tstate_scope(PyThreadState* ts)
	{
		_ts = PyThreadState_Swap(ts);
	}

	~swap_tstate_scope()
	{
		PyThreadState_Swap(_ts);
	}

private:

	PyThreadState* _ts;
};

// create new thread state for interpreter interp, make it current, and clean up on destruction
class thread_state
{
public:

	thread_state(PyInterpreterState* interp)
	{
		_ts = PyThreadState_New(interp);
		PyEval_RestoreThread(_ts);
	}

	~thread_state()
	{
		PyThreadState_Clear(_ts);
		PyThreadState_DeleteCurrent();
	}

	operator PyThreadState* ()
	{
		return _ts;
	}

	static PyThreadState* current()
	{
		return PyThreadState_Get();
	}

private:

	PyThreadState* _ts;
};

// represent a sub interpreter
class sub_interpreter
{
public:

	// perform the necessary setup and cleanup for a new thread running using a specific interpreter
	struct thread_scope
	{
		thread_state _state;
		swap_tstate_scope _swap{ _state };

		thread_scope(PyInterpreterState* interp) :
			_state(interp)
		{
		}
	};

	sub_interpreter()
	{
		restore_tstate_scope restore;

		_ts = Py_NewInterpreter();
	}

	~sub_interpreter()
	{
		if (_ts)
		{
			swap_tstate_scope sts(_ts);

			Py_EndInterpreter(_ts);
		}
	}

	PyInterpreterState* interp()
	{
		return _ts->interp;
	}

	static PyInterpreterState* current()
	{
		return thread_state::current()->interp;
	}

private:

	PyThreadState* _ts;
};



class PythonVM {
public:
	sub_interpreter* s_interp;
	PythonVM();

	void ExecCode(const char* s);

	void RunFunction(PyObjectCallback callback, const char* cstr_file, const char* cstr_function, PyArgs& args);

	~PythonVM();
};

class PythonVMMgr {
public:
	initialize* init;
	static PythonVMMgr* _one_instance;
	PythonVM* vm = NULL;
	static PythonVMMgr* GetVMMgr() {
		if (PythonVMMgr::_one_instance != NULL) {
			return PythonVMMgr::_one_instance;
		}
		PythonVMMgr::_one_instance = new PythonVMMgr();
		_one_instance->vm = new PythonVM();
		return PythonVMMgr::_one_instance;
	}
	PythonVMMgr() {
		PyImport_AppendInittab("file_internal", &PyFileInfoModule::FileInfoModuleInit);
		PyImport_AppendInittab("process_internal", &PyProcessInfoModule::ProcessInfoModuleInit);
		PyImport_AppendInittab("system_internal", &PySystemInfoModule::SystemInfoModuleInit);
		PyImport_AppendInittab("registry_internal", &PyRegistryUtilsModule::RegistryModuleInit);
		init = new initialize();
	}
	PythonVM* GetVM() {
		if (vm != NULL) {
			return vm;
		}
		vm = new PythonVM();
		return vm;
	}
	~PythonVMMgr() {
		delete init;
	}
};
#endif // !_PYTHON_UTILS_H