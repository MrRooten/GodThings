#pragma once
#include "public.h"
#include "StringUtils.h"
#include "VerifyUtils.h"
#include "PE.h"
#include "FileInfo.h"
#include <string>
class PEInfo : public FileInfo {
	std::wstring path;
	void Initialize(const wchar_t* path);
	SignatureInfomation* signatureInfo = NULL;
public:
	PEInfo(const WCHAR* path);

	PEInfo(const char* path);

	SignatureInfomation* GetSignatureInformation();

	std::vector<EXPORTED_FUNCTION> GetExportFunctions();

	std::vector<IMPORTED_FUNCTION> GetImportFunctions();

	std::vector<IMAGE_SECTION_HEADER> GetSections();


};