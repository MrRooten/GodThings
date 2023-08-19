#pragma once
#ifndef _NTFS_H_
#define _NTFS_H_
#include "ntapi.h"
#include "winioctl.h"
#include "utils.h"

#include <functional>

class NtfsQuery {

	enum USN_JOURNAL_RECORD {
		USN_RECORD_V2,
		USN_RECORD_V3,
		USN_RECORD_V4
	};

	HANDLE hVolume = INVALID_HANDLE_VALUE;
	GTWString path;
	USN_JOURNAL_DATA journalData;
public:
	NtfsQuery(const wchar_t* path);

	USN_JOURNAL_DATA QueryUSNInfo();

	using USNRecordProcess = std::function<bool(PUSN_RECORD)>;

	PVOID QueryUSNData(USNRecordProcess process);

};

#endif // !_NTFS_H_



