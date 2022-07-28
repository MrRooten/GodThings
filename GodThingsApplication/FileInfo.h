#pragma once
#include "NtFileInfo.h"
#include "public.h"
#include <string>
#include <string>
#include "StringUtils.h"
#include "FileUtils.h"
DWORD GetFileBasicInfo(LPCWSTR fileName, PFILE_BASIC_INFO* Pinfo);

class FileInfo {
public:
	HANDLE hFile = NULL;
	DWORD accessRights;
	pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)NULL;
	std::wstring fileName;
	FileInfo(const std::wstring &fileName) {
		this->fileName = fileName;
	}

	FileInfo(const std::string& fileName) {
		this->fileName = StringUtils::s2ws(fileName);
	}

	FileInfo(const char* fileName) {
		this->fileName = StringUtils::s2ws(fileName);
	}

	FileInfo(const wchar_t* fileName) {
		this->fileName = fileName;
	}
	PFILE_BASIC_INFORMATION pBasicInfo = NULL;
	DWORD SetBasicInfo();
	std::vector<std::wstring> GetAttributes();

	PFILE_STANDARD_INFORMATION pStandardInfo = NULL;
	DWORD SetStandInfo();

	PFILE_ACCESS_INFORMATION pAccessInfo = NULL;
	DWORD SetAccessInfo();

	PFILE_STAT_INFORMATION pStatInfo = NULL;
	DWORD SetStatInfo();

	PFILE_CASE_SENSITIVE_INFORMATION pCaseSensitiveInfo = NULL;
	DWORD SetCaseSensitiveInfo();

	PFILE_IO_PRIORITY_HINT_INFORMATION pIoPriorityHintInfo = NULL;
	DWORD SetIoPriorityHintInfo();

	PFILE_LINKS_INFORMATION pLinksInfo = NULL;
	DWORD SetLinksInfo();

	PFILE_PROCESS_IDS_USING_FILE_INFORMATION pProcessIdsUsingFileInfo = NULL;
	DWORD SetProcessIdsUsingFileInfo();

	PFILE_OBJECTID_INFORMATION pObjectIdInfo = NULL;
	DWORD SetObjectIdInfo();


};
//
//class PEFileInfo : public FileInfo {
//private:
//public:
//	PEFileInfo(std::wstring fileName) : FileInfo(fileName){
//
//	}
//	DWORD Parse();
//	~PEFileInfo();
//};

class FileMetrics {
public:
	uint32_t _a_start_time;
	uint32_t _a_duration;
	BytesBuffer _a_average_duration_s;
	uint32_t _a_average_duration_i;
	uint32_t _a_filename_offset;
	std::wstring filename;
	uint32_t _a_filename_nb_char;
};

class PrefetchFile {
	GTFile* f;
	BytesPair _bytes;
	bool is_compressed;
	uint32_t _format_version;
	BytesBuffer _unknown_values;
	uint32_t _file_size;
	BytesBuffer _exec_name;
	BytesBuffer _prefetch_hash;
	uint32_t _section_a;
	uint32_t _num_entries_a;
	uint32_t _a_index;
	FileMetrics _curMetrics;
	uint32_t _section_b;
	uint32_t _num_entries_b;
	uint32_t _section_c;
	uint32_t _length_c;
	uint32_t _section_d;
	uint32_t _num_entries_d;
	uint32_t _length_d;
	BytesBuffer _latest_exec_date;
	uint64_t _exec_count;
	void _process_section_a();
	void _process_section_c();

public:
	static PrefetchFile* Open(std::wstring file, bool is_compressed);
	PrefetchFile(std::wstring& file, bool is_compressed);
	DWORD Parse();
	FileMetrics& NextFileMetrics();
	std::vector<GTTime> GetExecTime();
	bool HasMoreFileMetrics();
	~PrefetchFile();
};

class DMPFile {

};

class AMCacheFile {

};

class JumpListFile {

};

class SRUMFile {
public:
	static SRUMFile* Open(std::wstring file);
	SRUMFile(std::wstring& file);
};

class ActivitiesCacheDB {
	
};

class EvtxEventRecord {
	BytesBuffer signature;
	uint32_t size;
	uint64_t event_record_id;
	uint64_t written_date;
	uint32_t event_offset;
	PBYTE evtx_bytes;
	uint32_t this_offset;
	BytesPair body;
public:
	EvtxEventRecord(PBYTE bytes, uint32_t offset);
	EvtxEventRecord();
	uint32_t GetSize();
};

class EvtxChunk {
	BytesBuffer signature;
	uint64_t first_event_record_number;
	uint64_t last_event_record_number;
	uint64_t first_event_record_id;
	uint64_t last_event_record_id;
	uint32_t header_size;
	uint32_t last_event_record_offset;
	uint32_t free_space_offset;
	uint32_t event_records_checksum;
	uint32_t checksum;
	PBYTE evtx_bytes;
	uint32_t this_offset;
	EvtxEventRecord curRecord;
	uint32_t cur_record_offset;
public:
	EvtxChunk(PBYTE bytes, uint32_t offset);
	EvtxChunk();
	EvtxEventRecord& NextRecord();

};

class EvtxFile {
	GTFile* f;
	BytesBuffer signature;
	BytesBuffer first_chunk_number;
	BytesBuffer last_chunk_number;
	BytesBuffer next_record_id;
	uint32_t header_size;
	uint32_t minor_format_version;
	uint32_t major_format_version;
	uint32_t header_block_size;
	uint32_t number_of_chunks;
	uint32_t file_flags;
	uint32_t checksum;
	EvtxChunk curChunk;
	uint32_t chk_index;
	PBYTE bytes;
public:
	static EvtxFile* Open(std::wstring file);
	EvtxFile(std::wstring& file);
	EvtxFile();
	DWORD Parse();
	EvtxChunk& NextChunk();
	~EvtxFile();
};
