#include "MagicUtils.h"
#include <stdio.h>
#include "utils.h"
FileMagic::FileMagic(){
	this->magic = NULL;
}
FileMagic::FileMagic(const CHAR* filename) {
	this->magic = magic_open(MAGIC_MIME_TYPE);
	auto load = magic_load(this->magic, filename);
}

const CHAR* FileMagic::FileFile(const CHAR* file) {
	return magic_file(this->magic, file);
}

const CHAR* FileMagic::FileBuffer(const PBYTE* buffer, size_t n) {
	return nullptr;
}

FileMagic* FileMagic::NewInstance(const CHAR* magic_file) {
	magic_set* magic = magic_open(MAGIC_NONE);
	auto ret = magic_load(magic, magic_file);
	if (ret < 0) {
		LOG_ERROR(L"LOAD magic.mgc failed");
		return NULL;
	}
	auto file_magic = new FileMagic();
	file_magic->magic = magic;
	return file_magic;
}

const CHAR* FileMagic::GetErrorString() {
	auto a = magic_error(this->magic);
	return a;
}

