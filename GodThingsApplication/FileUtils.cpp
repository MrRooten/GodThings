#include "FileUtils.h"

GTFile::GTFile() {

}

BOOL GTFile::Initialize(const LPWSTR filePath, DWORD mode) {
	this->hFile = CreateFileW(
		filePath,
		mode,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (this->hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	return TRUE;
}

DWORD GTFile::ReadBytes(PBYTE* pBytes) {
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
BytesPair GTFile::ReadAll() {
	PBYTE pBytes = NULL;
	auto size = this->ReadBytes(&pBytes);
	return BytesPair(pBytes,size);
}

DWORD GTFile::ReadBytes(PBYTE bytes,size_t size) {
	DWORD _size = 0;
	ReadFile(this->hFile, bytes, size, &_size, NULL);
	return _size;
}

//Return number of read bytes
DWORD GTFile::ReadBytesBlock(DWORD size, PBYTE* pBytes) {
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

size_t GTFile::WriteBytes(size_t pos, PBYTE bytes, size_t length) {
	DWORD a;

	WriteFile(this->hFile, bytes, length, &a, NULL);
	return a;
}

GTFile::~GTFile() {
	if (this->curBytes != NULL) {
		LocalFree(this->curBytes);
	}
}
GTFile* GTFileUtils::Open(LPCWSTR filePath,LPCWSTR mode) {
	GTFile* file = new GTFile();
	if (file == NULL) {
		return NULL;
	}
	DWORD access = 0;
	std::wstring_view m = mode;
	for (size_t i = 0; i < m.size(); i++) {
		if (m[i] == L'R' || m[i] == L'r') {
			access = access | GENERIC_READ;
		}
		else if (m[i] == L'W' || m[i] == L'w') {
			access = access | GENERIC_WRITE;
		}
		else if (m[i] == L'X' || m[i] == L'x') {
			access = access | GENERIC_EXECUTE;
		}
	}

	if (!file->Initialize((LPWSTR)filePath, access)) {
		delete file;
		return NULL;
	}


	return file;
}

Dir::Dir(const wchar_t* dirpath) {
	this->dirpath = dirpath;
}

std::vector<std::wstring> Dir::listFiles() {
	WIN32_FIND_DATAW ffd = { 0 };
	std::vector<std::wstring> res;
	std::wstring path;
	if (this->dirpath.ends_with(L"\\")) {
		path = this->dirpath + L"*";
	}
	else {
		path = this->dirpath + L"\\*";
	}
	HANDLE hFind = FindFirstFileW(path.c_str(), &ffd);
	do {
		res.push_back(ffd.cFileName);
		
	} while (FindNextFileW(hFind, &ffd) != 0);
	return res;
}





