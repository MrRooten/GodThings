#include "NtfsVolume.h"

#include "StringUtils.h"
NtfsQuery::NtfsQuery(const wchar_t* path) {
	this->path = path;
	this->hVolume = CreateFileW(path, 0x100, 3, NULL, 3, 0x80, 0);
	if (this->hVolume == INVALID_HANDLE_VALUE) {
		throw GTException(StringUtils::ws2s(GetLastErrorAsString()).c_str());
	}
}

USN_JOURNAL_DATA NtfsQuery::QueryUSNInfo() {
	LPVOID output = LocalAlloc(GPTR, 0x1000);
	USN_JOURNAL_DATA ret;
	DWORD outSize = 0;
	if (DeviceIoControl(this->hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &ret, 0x40, &outSize, NULL) == false) {
		throw GTException(StringUtils::ws2s(GetLastErrorAsString()).c_str());
	}
	
	return ret;
}

PVOID NtfsQuery::QueryUSNData(USNRecordProcess process) {
	PUSN_RECORD record;
	DWORD chunkSize = 0x100000;
	READ_USN_JOURNAL_DATA_V0 ReadData = { 0, 0xFFFFFFFF, FALSE, 0, 0 };
	auto JournalData = this->QueryUSNInfo();
	ReadData.UsnJournalID = JournalData.UsnJournalID;
	PVOID output = LocalAlloc(GPTR, chunkSize);
	DWORD bytesReturn = 0;
	bool isBreak = false;
	while (true) {
		if (DeviceIoControl(this->hVolume, FSCTL_READ_USN_JOURNAL, &ReadData, sizeof(ReadData), output, chunkSize, &bytesReturn, NULL) == false) {
			throw GTException(StringUtils::ws2s(GetLastErrorAsString()).c_str());
		}

		if (bytesReturn < 0x48) {
			break;
		}
		auto realRetBytes = bytesReturn - sizeof(USN);
		record = (PUSN_RECORD)(((PUCHAR)output) + sizeof(USN));
		while (realRetBytes > 0) {
			realRetBytes -= record->RecordLength;
			record = (PUSN_RECORD)((PUCHAR)record + record->RecordLength);
			if (process(record, this->hVolume) == false) {
				isBreak = true;
				break;
			}
		}

		if (isBreak) {
			break;
		}

		if (output == NULL) {
			break;
		}
		ReadData.StartUsn = *(USN*)output;
	}
	
	return PVOID();
}


