#include "PEInfo.h"

void PEInfo::Initialize(const wchar_t* path) {
	this->path = path;
	PE* pe = new PE();
	pe->AnalyseFile(path, true);
}

PEInfo::PEInfo(const WCHAR* path) {
	this->Initialize(path);
}

PEInfo::PEInfo(const char* path) {
	this->Initialize(StringUtils::s2ws(path).c_str());
}

SignatureInfomation* PEInfo::GetSignatureInformation() {
	if (this->signatureInfo != NULL) {
		return this->signatureInfo;
	}
	auto signature = VerifyEmbeddedSignature(this->path.c_str());
	this->signatureInfo = signature;
	return this->signatureInfo;
}
