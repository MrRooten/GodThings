#pragma once
#include <string>
#include <vector>
#include "public.h"

class File {
private:
	HANDLE hFile;
	DWORD mode;
	DWORD createMode;
	DWORD flagAttributes;
	size_t seek = 0;
	PBYTE curBytes = NULL;
	DWORD _blockSize = 0;
public:
	File();
	BOOL Initialize(std::wstring filePath,DWORD mode);
	DWORD ReadBytes(PBYTE *pBytes);
	DWORD ReadBytesBlock(DWORD size,PBYTE* pBytes);
	size_t WriteBytes(size_t pos, PBYTE bytes, size_t length);
	~File();
};

class FileUtils {
public:
	static File* Open(std::wstring filePath, std::wstring mode);
	static BOOL Delete(std::wstring filePath);
	static BOOL CreateLink(std::wstring filePath, std::wstring linkPath);
};

class Dir {
private:
	std::wstring dirpath;
public:
	Dir(const wchar_t* dirpath);
	std::vector<std::wstring> listFiles();
};