#include "FileUtils.h"

File::File() {

}

BOOL File::Initialize(std::wstring filePath, DWORD mode) {
	this->hFile = CreateFileW(
		filePath.c_str(),
		mode,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (this->hFile == NULL) {
		return FALSE;
	}
	return TRUE;
}

DWORD File::ReadBytes(PBYTE* pBytes) {
	LARGE_INTEGER size;
	if (!GetFileSizeEx(this->hFile, &size)) {
		*pBytes = NULL;
		return 0;
	}
	
	LONGLONG bufferSize = size.QuadPart;
	DWORD readSize;
	if (bufferSize > 0xffffffff) {
		bufferSize = 0xffffffff;
	}
	PBYTE res = (PBYTE)LocalAlloc(GPTR, bufferSize);
	if (res == NULL) {
		*pBytes = NULL;
		return 0;
	}

	if (!ReadFile(
		this->hFile,
		(LPVOID)res,
		bufferSize,
		&readSize,
		NULL
	)) {
		LocalFree(res);
		*pBytes = NULL;
		return NULL;
	}

	*pBytes = res;
	return readSize;
}

//Return number of read bytes
DWORD File::ReadBytesBlock(DWORD size, PBYTE* pBytes) {
	if (size != this->_blockSize) {
		if (this->curBytes != NULL) {
			LocalFree(this->curBytes);
		}
		this->curBytes = (PBYTE)LocalAlloc(GPTR, size);
		if (this->curBytes == NULL) {
			*pBytes = NULL;
			return 0;
		}
		this->_blockSize = size;
	}

	DWORD dwReadBytes = 0;
	if (!ReadFile(
		this->hFile,
		this->curBytes,
		this->_blockSize,
		&dwReadBytes,
		NULL
	)) {
		*pBytes = NULL;
		return 0;
	}

	*pBytes = this->curBytes;
	return dwReadBytes;
}

File::~File() {
	if (this->curBytes != NULL) {
		LocalFree(this->curBytes);
	}
}
File* FileUtils::Open(std::wstring filePath,std::wstring mode) {
	File* file = new File();
	if (file == NULL) {
		return file;
	}
	DWORD access = 0;
	for (size_t i = 0; i < mode.size(); i++) {
		if (mode[i] == L'R' || mode[i] == L'r') {
			access = access | GENERIC_READ;
		}
		else if (mode[i] == L'W' || mode[i] == L'w') {
			access = access | GENERIC_WRITE;
		}
		else if (mode[i] == L'X' || mode[i] == L'x') {
			access = access | GENERIC_EXECUTE;
		}
	}

	if (!file->Initialize(filePath, access)) {
		delete file;
		return NULL;
	}


	return file;
}