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
		(DWORD)bufferSize,
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
	ReadFile(this->hFile, bytes, (DWORD)size, &_size, NULL);
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

	WriteFile(this->hFile, bytes, (DWORD)length, &a, NULL);
	return a;
}

GTFile::~GTFile() {
	if (this->curBytes != NULL) {
		LocalFree(this->curBytes);
	}

	CloseHandle(this->hFile);
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

GTDir::GTDir(const wchar_t* dirpath) {
	this->dirpath = dirpath;
}

std::vector<std::wstring> GTDir::ListFiles() {
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

bool GTDir::IsDirExist() {
	auto attr = GetFileAttributesW(this->dirpath.c_str());
	return (attr != INVALID_FILE_ATTRIBUTES &&
		(attr & FILE_ATTRIBUTE_DIRECTORY));

}

bool GTDir::IsFileExist() {
	auto attr = GetFileAttributesW(this->dirpath.c_str());
	return attr != INVALID_FILE_ATTRIBUTES;
}

bool GTDir::CreateDir() {
	auto attr = GetFileAttributesW(this->dirpath.c_str());
	if (this->IsDirExist() == TRUE || this->IsFileExist() == TRUE) {
		return FALSE;
	}

	if (CreateDirectoryW(this->dirpath.c_str(), NULL)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

GTWString DisplayVolumePaths(
	__in PWCHAR VolumeName
)
{
	DWORD  CharCount = 4096;
	WCHAR Names[4096];
	PWCHAR NameIdx = NULL;
	BOOL   Success = FALSE;

	for (;;)
	{
		//
		//  Allocate a buffer to hold the paths.

		if (!Names)
		{
			//
			//  If memory can't be allocated, return.
			return L"";
		}

		//
		//  Obtain all of the paths
		//  for this volume.
		Success = GetVolumePathNamesForVolumeNameW(
			VolumeName, Names, CharCount, &CharCount
		);

		if (Success)
		{
			break;
		}

		if (GetLastError() != ERROR_MORE_DATA)
		{
			break;
		}

		//
		//  Try again with the
		//  new suggested size.
	}

	if (Success)
	{
		//
		//  Display the various paths.
		return Names;
	}


	return L"";
}

bool IsInitDevice = false;

std::map<GTWString, GTWString> DeviceToDrivers;

DWORD InitDevice(void) {
	DWORD  CharCount = 0;
	WCHAR  DeviceName[MAX_PATH] = L"";
	DWORD  Error = ERROR_SUCCESS;
	HANDLE FindHandle = INVALID_HANDLE_VALUE;
	BOOL   Found = FALSE;
	size_t Index = 0;
	BOOL   Success = FALSE;
	WCHAR  VolumeName[MAX_PATH] = L"";

	//
	//  Enumerate all volumes in the system.
	FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

	if (FindHandle == INVALID_HANDLE_VALUE)
	{
		Error = GetLastError();
		return Error;
	}

	for (;;)
	{
		//
		//  Skip the \\?\ prefix and remove the trailing backslash.
		Index = wcslen(VolumeName) - 1;

		if (VolumeName[0] != L'\\' ||
			VolumeName[1] != L'\\' ||
			VolumeName[2] != L'?' ||
			VolumeName[3] != L'\\' ||
			VolumeName[Index] != L'\\')
		{
			Error = ERROR_BAD_PATHNAME;
			break;
		}

		//
		//  QueryDosDeviceW does not allow a trailing backslash,
		//  so temporarily remove it.
		VolumeName[Index] = L'\0';

		CharCount = QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName));

		VolumeName[Index] = L'\\';

		if (CharCount == 0)
		{
			Error = GetLastError();
			//wprintf(L"QueryDosDeviceW failed with error code %d\n", Error);
			break;
		}

		DeviceToDrivers[DeviceName] = DisplayVolumePaths(VolumeName);

		//
		//  Move on to the next volume.
		Success = FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName));

		if (!Success)
		{
			Error = GetLastError();

			if (Error != ERROR_NO_MORE_FILES)
			{
				//wprintf(L"FindNextVolumeW failed with error code %d\n", Error);
				break;
			}

			//
			//  Finished iterating
			//  through all the volumes.
			Error = ERROR_SUCCESS;
			break;
		}
	}

	FindVolumeClose(FindHandle);
	FindHandle = INVALID_HANDLE_VALUE;

	IsInitDevice = true;
	return 0;
}

GTWString TryNTPathToDOSPath(const wchar_t* path) {
	if (IsInitDevice == false) {
		InitDevice();
	}
	GTWString volume_nt_name = path;
	if (volume_nt_name.starts_with(L"\\Device") == FALSE) {
		return path;
	}

	GTWString driver = L"";
	for (auto& kv : DeviceToDrivers) {
		if (volume_nt_name.starts_with(kv.first)) {
			driver = kv.second;
			volume_nt_name = driver + volume_nt_name.substr(kv.first.size() + 1);
			break;
		}
	}

	if (driver.size() == 0) {
		return path;
	}
	return volume_nt_name;
}

GTZip::GTZip(const wchar_t* zippath) {
	this->zippath = zippath;
}

bool GTZip::CreateZip() {
	return false;
}
