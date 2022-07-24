#include "utils.h"
#include "StringUtils.h"


INT16 MPEBytes::BytesToINT16(PBYTE bytes) {
	return bytes[0] << 8 + bytes[1];
}

INT32 MPEBytes::BytesToINT32(PBYTE bytes) {
	return bytes[0] << 24 + bytes[1] << 16 + bytes[2] << 8 + bytes[3];
}

INT64 MPEBytes::BytesToINT64(PBYTE bytes) {
	uint64_t value =
		static_cast<uint64_t>(bytes[7]) |
		static_cast<uint64_t>(bytes[6]) << 8 |
		static_cast<uint64_t>(bytes[5]) << 16 |
		static_cast<uint64_t>(bytes[4]) << 24 |
		static_cast<uint64_t>(bytes[3]) << 32 |
		static_cast<uint64_t>(bytes[2]) << 40 |
		static_cast<uint64_t>(bytes[1]) << 48 |
		static_cast<uint64_t>(bytes[0]) << 56;
	return value;
}

MPEBytes MPEBytes::INT16ToBytes(INT16 integer) {
	BYTE bytes[2];
	bytes[0] = integer >> 8;
	bytes[1] = integer & 0xff;
	return MPEBytes(bytes, 2);
}

MPEBytes MPEBytes::INT32ToBytes(INT32 integer) {
	BYTE bytes[4];
	bytes[0] = (integer & 0xff000000) >> 24;
	bytes[1] = (integer & 0x00ff0000) >> 16;
	bytes[2] = (integer & 0x0000ff00)>> 8;
	bytes[3] = (integer & 0xff);
	return MPEBytes(bytes, 4);
}

MPEBytes MPEBytes::INT64ToBytes(INT64 integer) {
	BYTE bytes[8];
	bytes[0] = (integer & 0xff00000000000000) >> 56;
	bytes[1] = (integer & 0x00ff000000000000) >> 48;
	bytes[2] = (integer & 0x0000ff0000000000) >> 40;
	bytes[3] = (integer & 0x000000ff00000000) >> 32;
	bytes[4] = (integer & 0x00000000ff000000)>> 24;
	bytes[5] = (integer & 0x0000000000ff0000)>> 16;
	bytes[6] = (integer & 0x000000000000ff00)>> 8;
	bytes[7] = integer & 0xff;
	return MPEBytes(bytes, 8);
}

MPEBytes::MPEBytes() {
	this->size = 0;
	this->bytes = (PBYTE)GlobalAlloc(GPTR, 0);
}

MPEBytes::MPEBytes(PBYTE bytes,size_t size) {
	if (this->size == 0) {
		this->bytes = (PBYTE)GlobalAlloc(GPTR, sizeof(BYTE) * size);
	}

	if (this->bytes == NULL) {
		this->error = GetLastError();
		return;
	}

	memcpy(this->bytes, bytes, size * sizeof(BYTE));
	this->size = size;
}

PBYTE MPEBytes::ToBytes() {
	return this->bytes;
}

VOID MPEBytes::AddBytes(PBYTE bytes,size_t size) {
	this->bytes = (PBYTE)GlobalReAlloc(this->bytes, this->size + size, GMEM_MOVEABLE);
	if (this->bytes == NULL) {
		this->error = GetLastError();
		return;
	}

	memcpy(this->bytes + this->size, bytes, size);
	this->size += size;
}

VOID MPEBytes::AddBytes(MPEBytes& mpeBytes) {
	PBYTE bytes = mpeBytes.ToBytes();
	size_t size = mpeBytes.size;
	this->bytes = (PBYTE)GlobalReAlloc(this->bytes, this->size + size, GMEM_MOVEABLE);
	if (this->bytes == NULL) {
		this->error = GetLastError();
		return;
	}

	memcpy(this->bytes + this->size, bytes, size);
	this->size += size;
}

MPEBytes::~MPEBytes() {
	GlobalFree((HGLOBAL)this->bytes);
}

VOID GTPrintln(const WCHAR* messageFormat, ...) {
	wchar_t buffer[1024] = { 0 };
	va_list vaList;//equal to Format + sizeof(FOrmat)
	va_start(vaList, messageFormat);
	_vsnwprintf(buffer, 1024, messageFormat, vaList);
	va_end(vaList);
	
	if (sizeof(TCHAR) != sizeof(CHAR)) {
		wprintf(L"%s\n", buffer);
	}
	else {
		const char* c = StringUtils::ws2s(buffer).c_str();
		printf_s("%s\n", c);
	}
}

VOID Logln(LOG_LEVEL logLevel, const WCHAR* messageFormat, ...) {
	wchar_t buffer[255] = { 0 };
	va_list vaList;//equal to Format + sizeof(FOrmat)
	va_start(vaList, messageFormat);
	_vsnwprintf(buffer, 255, messageFormat, vaList);
	va_end(vaList);

	if (logLevel <= GlobalLogLevel) {
		if (logLevel == DEBUG_LEVEL) {
			if (sizeof(TCHAR) != sizeof(CHAR))
				wprintf(L"[DBG]:%s\n", buffer);
			else {
				const char* c = StringUtils::ws2s(buffer).c_str();
				printf("[DBG]:%s\n", c);
			}
		}
		else if (logLevel == INFO_LEVEL) {
			if (sizeof(TCHAR) != sizeof(CHAR))
				wprintf(L"[INF]:%s\n", buffer);
			else {
				const char* c = StringUtils::ws2s(buffer).c_str();
				printf("[INF]:%s\n", c);
			}
		}
		else if (logLevel == WARNING_LEVEL) {
			if (sizeof(TCHAR) != sizeof(CHAR))
				wprintf(L"[WRN]:%s\n", buffer);
			else {
				const char* c = StringUtils::ws2s(buffer).c_str();
				printf("[WRN]:%s\n", c);
			}
		}
		else if (logLevel == ERROR_LEVEL) {
			if (sizeof(TCHAR) != sizeof(CHAR))
				wprintf(L"[ERR]:%s\n", buffer);
			else {
				const char* c = StringUtils::ws2s(buffer).c_str();
				printf("[ERR]:%s\n", c);
			}
		}
	}
}
static wchar_t message[100];
LPWSTR GetLastErrorAsString() {
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	ZeroMemory(message, 0, sizeof(WCHAR) * 100);
	WCHAR *messageBuffer = message;
	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::wstring message(messageBuffer, size);

	//Free the Win32's string's buffer.
	return messageBuffer;
}

std::wstring GetLastErrorAsStringThreadSafe() {
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	ZeroMemory(message, 0, sizeof(WCHAR) * 100);
	WCHAR* messageBuffer = message;
	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::wstring message(messageBuffer, size);

	//Free the Win32's string's buffer.
	return message;
}
std::wstring s2ws(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

std::wstring GTTime::ToString() {
	WCHAR buf[100];
	swprintf_s(buf, L"%d-%02d-%02d %02d:%02d:%02d",this->year,this->mouth,this->day,this->hour,this->minute,this->second);
	return buf;
}

ULONG64 GTTime::ToNowULONG64() {
	ULONG64 res = 0;
	res += this->millisecond;
	res += this->second * 1000;
	res += this->minute * 60 * 1000;
	res += this->hour * 60 * 60 * 1000;
	res += this->day * 24 * 60 * 60 * 1000;
	return res;
}
GTTime::GTTime(FILETIME &filetime) {
	SYSTEMTIME utc;
	FileTimeToSystemTime(std::addressof(filetime), std::addressof(utc));
	std::ostringstream stm;
	const auto w2 = std::setw(2);
	this->year = utc.wYear;
	this->mouth = utc.wMonth;
	this->day = utc.wDay;
	this->hour = utc.wHour;
	this->minute = utc.wMinute;
	this->second = utc.wSecond;
	this->millisecond = utc.wMilliseconds;
}
GTTime::GTTime(SYSTEMTIME &utc) {
	std::ostringstream stm;
	const auto w2 = std::setw(2);
	this->year = utc.wYear;
	this->mouth = utc.wMonth;
	this->day = utc.wDay;
	this->hour = utc.wHour;
	this->minute = utc.wMinute;
	this->second = utc.wSecond;
	this->millisecond = utc.wMilliseconds;
}
std::wstring GTTime::ToISO8601() {
	struct std::tm tm;
	std::wstringstream ss(this->ToString().c_str());
	ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S"); // or just %T in this case
	std::time_t t = mktime(&tm);

	time(&t);
	WCHAR buf[sizeof L"2011-10-08T07:07:09Z"];
	wcsftime(buf, sizeof buf, L"%FT%TZ", gmtime(&t));

	std::wstring res = buf;

	res.replace(res.end()-1, res.end(), L".000Z");
	return res;
}