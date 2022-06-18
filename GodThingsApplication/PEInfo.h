#pragma once
#include "public.h"
#include "StringUtils.h"
#include "VerifyUtils.h"
#include "PE.h"
#include <string>
class PEInfo {
	std::wstring path;
	void Initialize(const wchar_t* path);
	SignatureInfomation* signatureInfo = NULL;
public:
	PEInfo(const WCHAR* path);

	PEInfo(const char* path);

	SignatureInfomation* GetSignatureInformation();
};