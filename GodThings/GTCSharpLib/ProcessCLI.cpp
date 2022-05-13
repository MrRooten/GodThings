#include "pch.h"
#include "ProcessCLI.h"
#include "ObjectInfo.h"


namespace GodAgent {
	MemoryStateCLI^ ProcessCLI::GetMemoryState() {
		if (this->Memory == nullptr) {
			this->Memory = gcnew MemoryStateCLI();
			if (this->Memory == nullptr) {
				return nullptr;
			}
		}

		this->_process->SetProcessMemoryState();
		this->Memory->PeakVirtualSize = this->_process->memoryState->PeakVirtualSize;
		this->Memory->VirtualSize = this->_process->memoryState->VirtualSize;
		this->Memory->PageFaultCount = this->_process->memoryState->PageFaultCount;
		this->Memory->PeakWorkingSetSize = this->_process->memoryState->PeakWorkingSetSize;
		this->Memory->WorkingSetSize = this->_process->memoryState->WorkingSetSize;
		this->Memory->QuotaPeakPagedPoolUsage = this->_process->memoryState->QuotaPeakPagedPoolUsage;
		this->Memory->QuotaPagedPoolUsage = this->_process->memoryState->QuotaPagedPoolUsage;
		this->Memory->QuotaPeakNonPagedPoolUsage = this->_process->memoryState->QuotaPeakNonPagedPoolUsage;
		this->Memory->QuotaNonPagedPoolUsage = this->_process->memoryState->QuotaNonPagedPoolUsage;
		this->Memory->PagefileUsage = this->_process->memoryState->PagefileUsage;
		this->Memory->PeakPagefileUsage = this->_process->memoryState->PeakPagefileUsage;
		this->Memory->PrivateUsage = this->_process->memoryState->PrivateUsage;
		this->Memory->PrivateWorkingSetSize = this->_process->memoryState->PrivateWorkingSetSize;
		this->Memory->SharedCommitUsage = this->_process->memoryState->SharedCommitUsage;
		return this->Memory;
	}

	SecurityStateCLI^ ProcessCLI::GetSecurityState() {
		if (this->Security == nullptr) {
			this->Security = gcnew SecurityStateCLI();
			if (this->Security == nullptr)
				return nullptr;
		}

		this->_process->SetProcessSecurityState();
		auto _Sids = this->_process->securityState->GetSIDsString();
		for (auto sid : _Sids) {
			this->Security->Sids.Add(gcnew String(sid.c_str()));
		}

		auto _Privileges = this->_process->securityState->GetPrivilegesAsString();
		for (auto _privilege : _Privileges) {
			this->Security->Privileges.Add(gcnew String(_privilege.c_str()));
		}

		auto _Integrity = this->_process->securityState->GetIntegrityAsString();
		this->Security->Integrity = gcnew String(_Integrity.c_str());
		return this->Security;
	}

	String^ ProcessCLI::GetUser() {
		this->User = gcnew String(this->_process->GetUser().c_str());
		return this->User;
	}

	void ProcessCLI::GetHandleState() {
		this->_process->SetProcessHandleState();
		for (int i = 0; i < this->_process->handleState->handles->NumberOfHandles;i++) {
			HandleCLI^ handle = gcnew HandleCLI();
			handle->Type = gcnew String(ObjectInfo::GetTypeName(this->_process->handleState->handles->Handles[i].HandleValue).c_str());
			handle->Name = gcnew String(ObjectInfo::GetObjectName(this->_process->handleState->handles->Handles[i].HandleValue).c_str());
			handle->PointerCount = this->_process->handleState->handles->Handles[i].PointerCount;
			handle->HandleCount = this->_process->handleState->handles->Handles[i].HandleCount;
			handle->Access = this->_process->handleState->handles->Handles[i].GrantedAccess;
			this->Handles.Add(handle);
		}
		
	}

	ImageStateCLI^ ProcessCLI::GetImageState() {
		if (this->Image == nullptr) {
			this->Image = gcnew ImageStateCLI();
			if (this->Image == nullptr)
				return nullptr;
		}

		if (this->_process->imageState == NULL) {
			this->_process->SetProcessImageState();
		}

		this->Image->CmdLine = gcnew String(this->_process->imageState->cmdline.c_str());
		this->Image->ImageFileName = gcnew String(this->_process->imageState->imageFileName.c_str());
		return this->Image;
	}


	ProcessCLI::ProcessCLI(Process* process) {
		this->ProcessId = process->processId;
		this->Name = gcnew String(process->processName.c_str());
		this->_process = process;
	}

	ProcessCLI::ProcessCLI(UInt32 pid) {
		this->_process = new Process(pid);

		_isCreateByThis = true;
	}

	ProcessCLI::~ProcessCLI() {
		if (_isCreateByThis) {
			delete this->_process;
		}
	}


}