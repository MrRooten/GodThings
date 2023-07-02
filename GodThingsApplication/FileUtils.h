#pragma once
#ifndef _FILE_UTILS_H
#define _FILE_UTILS_H


#include <string>
#include <vector>
#include <map>
#include "public.h"
#include "utils.h"
class GTFile {
private:
	HANDLE hFile;
	DWORD mode;
	DWORD createMode;
	DWORD flagAttributes;
	size_t seek = 0;
	PBYTE curBytes = NULL;
	DWORD _blockSize = 0;
public:
	GTFile();
	BOOL Initialize(LPWSTR filePath,DWORD mode);
	DWORD ReadBytes(PBYTE *pBytes);
	
	BytesPair ReadAll();
	DWORD ReadBytes(PBYTE bytes,size_t size);
	DWORD ReadBytesBlock(DWORD size,PBYTE* pBytes);
	size_t WriteBytes(size_t pos, PBYTE bytes, size_t length);
	~GTFile();
};

class GTFileUtils {
public:
	static GTFile* Open(LPCWSTR filePath, LPCWSTR mode);
	static BOOL Delete(const LPWSTR filePath);
	static BOOL CreateLink(const LPWSTR filePath, const LPWSTR linkPath);
};

class GTDir {
private:
	std::wstring dirpath;
public:
	GTDir(const wchar_t* dirpath);
	std::vector<std::wstring> ListFiles();
	bool IsDirExist();
	bool IsFileExist();
	bool CreateDir();
};

class MFTReader {
	std::wstring volume;
public:
	MFTReader(std::wstring volume);
	DWORD Initialize();
};

class GTZip {
private:
	std::wstring zippath;
public:
	GTZip(const wchar_t* zippath);
	bool CreateZip();
	bool AddFile();
	bool AddDir(const wchar_t* dirpath);
	bool Close();
};
GTWString TryNTPathToDOSPath(const wchar_t* path);
#endif // !_FILE_UTILS_H