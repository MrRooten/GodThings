#pragma once
#pragma managed
#include "Process.h"
using namespace System;
using namespace System::Collections;

namespace GodAgent {
	public ref class SecurityStateCLI {
	public:
		ArrayList Sids;
		ArrayList Privileges;
		array<String^>^ Groups;
		String^ Session;
		String^ ImpersonationLevel;
		String^ Integrity;

	};

	public ref class CPUStateCLI {
	public:
		UInt32 LowCreateTime;
		UInt32 HighCreateTime;
		UInt32 LowExitTime;
		UInt32 HighExitTime;
		UInt32 LowKernelTime;
		UInt32 HighKernelTime;

		String^ priority;
		UInt64 cycles;
		UInt32 RecordTime;
	};

	public ref class MemoryStateCLI {
	public:
		UInt64 PeakVirtualSize;
		UInt64 VirtualSize;
		UInt32 PageFaultCount;
		UInt64 PeakWorkingSetSize;
		UInt64 WorkingSetSize;
		UInt64 QuotaPeakPagedPoolUsage;
		UInt64 QuotaPagedPoolUsage;
		UInt64 QuotaPeakNonPagedPoolUsage;
		UInt64 QuotaNonPagedPoolUsage;
		UInt64 PagefileUsage;
		UInt64 PeakPagefileUsage;
		UInt64 PrivateUsage;
		UInt64 PrivateWorkingSetSize;
		UInt64 SharedCommitUsage;
	};

	public ref class IOStateCLI {
	public:
		String^ Priority;
		UInt64 ReadOperationCount;
		UInt64 WriteOperationCount;
		UInt64 OtherOperationCount;
		UInt64 ReadTransferCount;
		UInt64 WriteTransferCount;
		UInt64 OtherTransferCount;
	};

	public ref class HandleCLI {
	public:
		String^ Name;
		String^ Type;
		UInt64 HandleCount;
		UInt64 PointerCount;
		UInt32 Access;
	};

	public ref class ImageStateCLI {
	public:
		String^ ImageFileName;
		String^ CmdLine;
	};

	public ref class ProcessCLI {
	private:
		Process* _process;
		Boolean _isCreateByThis;
	public:
		String^ Name;
		int ProcessId;
		String^ User;
		String^ GetUser();
		ArrayList Handles;
		void GetHandleState();
		ImageStateCLI^ Image;
		ImageStateCLI^ GetImageState();
		IOStateCLI^ IO;
		//IOStateCLI^ GetIOState();
		SecurityStateCLI^ Security;
		SecurityStateCLI^ GetSecurityState();
		CPUStateCLI^ NewCPU;
		CPUStateCLI^ OldCPU;
		//void SetCPUState();
		MemoryStateCLI^ Memory;
		MemoryStateCLI^ GetMemoryState();
		ProcessCLI(Process* process);
		ProcessCLI(UInt32 pid);
		~ProcessCLI();
	};

	public ref class ProcessManagerCLI {
	public:
		//array<ProcessCLI^>^ GetProcesses();
		//void UpdateState();
	};
}