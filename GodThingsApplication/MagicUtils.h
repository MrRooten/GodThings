#pragma once
#include "public.h"
#include "magic.h"
class FileMagic {
	magic_set* magic;
public:
	FileMagic();
	FileMagic(const CHAR* magic_file);
	const CHAR* FileFile(const CHAR* file);
	const CHAR* FileBuffer(const PBYTE* buffer, size_t n);
	static FileMagic* NewInstance(const CHAR* magic_file);
	const CHAR* GetErrorString();
};
