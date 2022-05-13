#pragma once
#include "NtFileInfo.h"
#include "public.h"
#include <string>
#include <string>
#include "StringUtils.h"
DWORD GetFileBasicInfo(LPCWSTR fileName, PFILE_BASIC_INFO* Pinfo);

class FileInfo {
public:
	HANDLE hFile = NULL;
	DWORD accessRights;
	pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)NULL;
	std::wstring fileName;
	FileInfo(const std::wstring &fileName) {
		this->fileName = fileName;
	}

	FileInfo(const std::string& fileName) {
		this->fileName = StringUtils::s2ws(fileName);
	}

	FileInfo(const char* fileName) {
		this->fileName = StringUtils::s2ws(fileName);
	}

	FileInfo(const wchar_t* fileName) {
		this->fileName = fileName;
	}
	PFILE_BASIC_INFORMATION pBasicInfo = NULL;
	DWORD SetBasicInfo();
	std::vector<std::wstring> GetAttributes();

	PFILE_STANDARD_INFORMATION pStandardInfo = NULL;
	DWORD SetStandInfo();

	PFILE_ACCESS_INFORMATION pAccessInfo = NULL;
	DWORD SetAccessInfo();

	PFILE_STAT_INFORMATION pStatInfo = NULL;
	DWORD SetStatInfo();

	PFILE_CASE_SENSITIVE_INFORMATION pCaseSensitiveInfo = NULL;
	DWORD SetCaseSensitiveInfo();

	PFILE_IO_PRIORITY_HINT_INFORMATION pIoPriorityHintInfo = NULL;
	DWORD SetIoPriorityHintInfo();

	PFILE_LINKS_INFORMATION pLinksInfo = NULL;
	DWORD SetLinksInfo();

	PFILE_PROCESS_IDS_USING_FILE_INFORMATION pProcessIdsUsingFileInfo = NULL;
	DWORD SetProcessIdsUsingFileInfo();

	PFILE_OBJECTID_INFORMATION pObjectIdInfo = NULL;
	DWORD SetObjectIdInfo();


};
//
//class PEFileInfo : public FileInfo {
//private:
//public:
//	PEFileInfo(std::wstring fileName) : FileInfo(fileName){
//
//	}
//	DWORD Parse();
//	~PEFileInfo();
//};