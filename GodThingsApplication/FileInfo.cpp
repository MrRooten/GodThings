#include "FileInfo.h"
#include <ntstatus.h>

DWORD GetFileBasicInfo(LPCWSTR fileName, PFILE_BASIC_INFO* Pinfo) {
	PFILE_BASIC_INFO info = (PFILE_BASIC_INFO)GlobalAlloc(GPTR, sizeof(FILE_BASIC_INFO));
	if (info == NULL) {
		return GetLastError();
	}

	pNtQueryInformationFile NtQueryInfomationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
	if (NtQueryInfomationFile == NULL) {
		return GetLastError();
	}

	HANDLE hFile = CreateFileW(fileName,
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == NULL) {
		return GetLastError();
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInfomationFile(
		hFile,
		&block,
		info,
		sizeof(FILE_BASIC_INFO),
		FileBasicInformation
	);

	return 0;
}

DWORD FileInfo::SetBasicInfo() {
	if (this->pBasicInfo == NULL) {
		this->pBasicInfo = (PFILE_BASIC_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_BASIC_INFORMATION);
		if (this->pBasicInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pBasicInfo, sizeof FILE_BASIC_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pBasicInfo,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

std::vector<std::wstring> FileInfo::GetAttributes() {
	std::vector<std::wstring> res;
	if (this->pBasicInfo == NULL) {
		if (this->SetBasicInfo() != ERROR_SUCCESS) {
			return res;
		}
	}
	
	auto &attrs = this->pBasicInfo->FileAttributes;
	if (attrs & FILE_ATTRIBUTE_ARCHIVE) {
		res.push_back(L"FILE_ATTRIBUTE_ARCHIVE");
	}
	if (attrs & FILE_ATTRIBUTE_COMPRESSED) {
		res.push_back(L"FILE_ATTRIBUTE_COMPRESSED");
	}
	if (attrs & FILE_ATTRIBUTE_DEVICE) {
		res.push_back(L"FILE_ATTRIBUTE_DEVICE");
	}
	if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
		res.push_back(L"FILE_ATTRIBUTE_DIRECTORY");
	}
	if (attrs & FILE_ATTRIBUTE_ENCRYPTED) {
		res.push_back(L"FILE_ATTRIBUTE_ENCRYPTED");
	}
	if (attrs & FILE_ATTRIBUTE_HIDDEN) {
		res.push_back(L"FILE_ATTRIBUTE_HIDDEN");
	}
	if (attrs & FILE_ATTRIBUTE_INTEGRITY_STREAM) {
		res.push_back(L"FILE_ATTRIBUTE_INTEGRITY_STREAM");
	}
	if (attrs & FILE_ATTRIBUTE_NORMAL) {
		res.push_back(L"FILE_ATTRIBUTE_NORMAL");
	}
	if (attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
		res.push_back(L"FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
	}
	if (attrs & FILE_ATTRIBUTE_NO_SCRUB_DATA) {
		res.push_back(L"FILE_ATTRIBUTE_NO_SCRUB_DATA");
	}
	if (attrs & FILE_ATTRIBUTE_OFFLINE) {
		res.push_back(L"FILE_ATTRIBUTE_OFFLINE");
	}
	if (attrs & FILE_ATTRIBUTE_READONLY) {
		res.push_back(L"FILE_ATTRIBUTE_READONLY");
	}
	if (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) {
		res.push_back(L"FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS");
	}
	if (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN) {
		res.push_back(L"FILE_ATTRIBUTE_RECALL_ON_OPEN");
	}
	if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
		res.push_back(L"FILE_ATTRIBUTE_REPARSE_POINT");
	}
	if (attrs & FILE_ATTRIBUTE_SPARSE_FILE) {
		res.push_back(L"FILE_ATTRIBUTE_SPARSE_FILE");
	}
	if (attrs & FILE_ATTRIBUTE_SYSTEM) {
		res.push_back(L"FILE_ATTRIBUTE_SYSTEM");
	}
	if (attrs & FILE_ATTRIBUTE_TEMPORARY) {
		res.push_back(L"FILE_ATTRIBUTE_TEMPORARY");
	}
	if (attrs & FILE_ATTRIBUTE_VIRTUAL) {
		res.push_back(L"FILE_ATTRIBUTE_VIRTUAL");
	}
	return res;
}

DWORD FileInfo::SetStandInfo() {
	if (this->pStandardInfo == NULL) {
		this->pStandardInfo = (PFILE_STANDARD_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_STANDARD_INFORMATION);
		if (this->pStandardInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pStandardInfo, sizeof FILE_STANDARD_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pStandardInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetAccessInfo() {
	if (this->pAccessInfo == NULL) {
		this->pAccessInfo = (PFILE_ACCESS_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_ACCESS_INFORMATION);
		if (this->pAccessInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pAccessInfo, sizeof FILE_ACCESS_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pAccessInfo,
		sizeof(FILE_ACCESS_INFORMATION),
		FileAccessInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetStatInfo() {
	if (this->pStatInfo == NULL) {
		this->pStatInfo = (PFILE_STAT_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_STAT_INFORMATION);
		if (this->pStatInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pStatInfo, sizeof FILE_STAT_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pStatInfo,
		sizeof(FILE_STAT_INFORMATION),
		FileStatInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetCaseSensitiveInfo() {
	if (this->pCaseSensitiveInfo == NULL) {
		this->pCaseSensitiveInfo = (PFILE_CASE_SENSITIVE_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_CASE_SENSITIVE_INFORMATION);
		if (this->pCaseSensitiveInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pCaseSensitiveInfo, sizeof FILE_CASE_SENSITIVE_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pCaseSensitiveInfo,
		sizeof(FILE_CASE_SENSITIVE_INFORMATION),
		FileCaseSensitiveInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetProcessIdsUsingFileInfo() {
	if (this->pProcessIdsUsingFileInfo == NULL) {
		this->pProcessIdsUsingFileInfo = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)GlobalAlloc(GPTR, sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION)+sizeof(ULONG_PTR)*1023);
		if (this->pProcessIdsUsingFileInfo == NULL) {
			return GetLastError();
		}
	}

	ZeroMemory(this->pProcessIdsUsingFileInfo, sizeof FILE_PROCESS_IDS_USING_FILE_INFORMATION);
	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pProcessIdsUsingFileInfo,
		sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION)+1023*sizeof(ULONG_PTR),
		FileProcessIdsUsingFileInformation
	);

	if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
		this->pProcessIdsUsingFileInfo = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)\
			GlobalReAlloc(hFile, sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) + sizeof(ULONG_PTR) * 2047,GPTR);
		if (this->pProcessIdsUsingFileInfo == NULL) {
			return GetLastError();
		}
		status = NtQueryInformationFile(
			hFile,
			&block,
			this->pProcessIdsUsingFileInfo,
			sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) + 2047 * sizeof(ULONG_PTR),
			FileProcessIdsUsingFileInformation
		);
	}
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetIoPriorityHintInfo() {
	if (this->pIoPriorityHintInfo == NULL) {
		this->pIoPriorityHintInfo = (PFILE_IO_PRIORITY_HINT_INFORMATION)GlobalAlloc(GPTR, sizeof FILE_IO_PRIORITY_HINT_INFORMATION);
		if (this->pIoPriorityHintInfo == NULL) {
			return GetLastError();
		}
	}

	HANDLE hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL) {
		return GetLastError();
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	IO_STATUS_BLOCK block;
	NTSTATUS status = NtQueryInformationFile(
		hFile,
		&block,
		this->pIoPriorityHintInfo,
		sizeof(FILE_IO_PRIORITY_HINT_INFORMATION),
		FileIoPriorityHintInformation
	);
	CloseHandle(hFile);
	return NtStatusHandler(status);
}

DWORD FileInfo::SetLinksInfo() {
	DWORD status;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK block;
	NTSTATUS NtStatus;
	DWORD size = 0x100;
	if (this->pLinksInfo == NULL) {
		this->pLinksInfo = (PFILE_LINKS_INFORMATION)LocalAlloc(GPTR, size);
		if (this->pLinksInfo == NULL) {
			status = GetLastError();
			goto CleanUp;
		}
	}

	hFile = CreateFileW(this->fileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == NULL) {
		status = GetLastError();
		goto CleanUp;
	}

	if (this->NtQueryInformationFile == NULL) {
		this->NtQueryInformationFile = (pNtQueryInformationFile)GetNativeProc("NtQueryInformationFile");
		if (this->NtQueryInformationFile == NULL) {
			CloseHandle(hFile);
			return GetLastError();
		}
	}
	
	NtStatus = NtQueryInformationFile(
		hFile,
		&block,
		this->pLinksInfo,
		size,
		FileHardLinkInformation
	);
	if (NtStatus != STATUS_BUFFER_OVERFLOW && NtStatus != STATUS_BUFFER_TOO_SMALL && NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
		status = NtStatusHandler(NtStatus);
		goto CleanUp;
	}

	if (NtStatus == STATUS_BUFFER_OVERFLOW || NtStatus == STATUS_BUFFER_TOO_SMALL || NtStatus == STATUS_INFO_LENGTH_MISMATCH) {
		int i = 0;
		do {
			size = size * 2;
			this->pLinksInfo = (PFILE_LINKS_INFORMATION)LocalReAlloc(this->pLinksInfo, size, GPTR | GMEM_MOVEABLE);
			if (this->pLinksInfo == NULL) {
				status = GetLastError();
				goto CleanUp;
			}
			NtStatus = NtQueryInformationFile(
				hFile,
				&block,
				this->pLinksInfo,
				size,
				FileHardLinkInformation
			);
			i++;
		} while ((NtStatus == STATUS_BUFFER_OVERFLOW || NtStatus == STATUS_BUFFER_TOO_SMALL || NtStatus == STATUS_INFO_LENGTH_MISMATCH)&&i < 10);
	}
	status = NtStatusHandler(NtStatus);
CleanUp:
	if (hFile != NULL) {
		CloseHandle(hFile);
	}


	return status;
}

//DWORD PEFileInfo::Parse() {
//	return 0;
//}
