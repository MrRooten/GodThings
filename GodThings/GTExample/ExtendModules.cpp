#include "tinyxml2.h"
#include "ExtendModules.h"
#include "RegistryUtils.h"
#include "EvtInfo.h"
#include <vector>
LastShutdown::LastShutdown() {
	this->Name = L"LastShutdown";
	this->Path = L"System";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get Last shutdown time";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* LastShutdown::ModuleRun() {
	ResultSet* result = new ResultSet();
	auto v = RegistryUtils::GetValueStatic(L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Windows", L"ShutdownTime");
	auto t = get_u64l(v.c_str());
	FILETIME ft;
	ft.dwLowDateTime = t && 0xffffffff;
	ft.dwHighDateTime = t >> 32;
	GTTime gTime(ft);
	result->PushDictOrdered("LastShutdown", StringUtils::ws2s(gTime.String()));
	result->SetType(DICT);
	return result;
}

BAMParse::BAMParse() {
	this->Name = L"BAMParse";
	this->Path = L"System";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"BAMParse";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* BAMParse::ModuleRun() {
	ResultSet* result = new ResultSet();
	GTWString path = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
	RegistryUtils utils(path);
	auto keys = utils.ListSubKeys();
	for (auto& key : keys) {
		auto target = path + L"\\" + key;
		RegistryUtils sidRegistry(target);
		auto names = sidRegistry.ListValueNames();
		for (auto& name : names) {
			RegistryUtils _get_type(target.c_str());
			DWORD type = 0;
			auto ret = _get_type.GetValueType(name.c_str(), &type);
			if (ret != 0) {
				continue;
			}

			if (type != REG_BINARY) {
				continue;
			}
			auto v = RegistryUtils::GetValueStatic(target.c_str(), name.c_str());
			auto utc = get_u64l(v.c_str());
			auto time = GTTime::FromTimeStamp64(utc);
			result->PushDictOrdered("sid", StringUtils::ws2s(key));
			result->PushDictOrdered("exe", StringUtils::ws2s(name));
			result->PushDictOrdered("time", StringUtils::ws2s(time.String()));
		}
	}
	result->SetType(DICT);
	return result;
}

JumpListData::JumpListData() {
	this->Name = L"JumpListData";
	this->Path = L"Registry";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Registry JumpListData";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* JumpListData::ModuleRun() {
	ResultSet* result = new ResultSet();
	auto s = L"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData";
	RegistryUtils utils(s);
	auto names = utils.ListValueNames();
	for (auto& name : names) {
		auto v = RegistryUtils::GetValueStatic(s, name.c_str());
		auto s = get_u64l(v.data());
		auto exec = GTTime::FromTimeStamp64(s);
		result->PushDictOrdered("name", StringUtils::ws2s(name));
		result->PushDictOrdered("exec", StringUtils::ws2s(exec.String()));
	}
	result->SetType(DICT);
	return result;
}
#include "OtherInfo.h"
ListSSP::ListSSP() {
	this->Name = L"ListSSP";
	this->Path = L"Other";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"List Security Provider";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ListSSP::ModuleRun() {
	auto providers = SecurityProvider::ListProviders();
	for (auto& provider : providers) {
		wprintf(L"%s %s\n", provider.GetName().c_str(), provider.GetComment().c_str());
	}
	return nullptr;
}

RDPSessions::RDPSessions() {
	this->Name = L"RDPSessions";
	this->Path = L"EventLog";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Enum Sessions logs";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

class Event21{
public:
	int	event_id;
	GTString time_creation;
	int process_id;
	int thread_id;
	GTString computer;
	GTString suid;
	GTString user;
	int record_id;
	int session_id;
	GTString address;

	Event21(const char* xml);
	Event21();
};

Event21::Event21(const char* xml) {
	tinyxml2::XMLDocument doc;
	doc.Parse(xml);
	auto root_element = doc.RootElement();
	auto system_element = root_element->FirstChildElement();
	auto next = system_element->FirstChildElement();
	auto user_element = system_element->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;
	while (next) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "EventId") == 0) {
			this->event_id = stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = stoi(tid->Value());
			}
		}
		else if (_strcmpi(name, "Computer") == 0) {
			this->computer = value;
		}
		else if (_strcmpi(name, "Security") == 0) {
			auto suid = next->FindAttribute("UserID");
			if (suid != NULL) {
				this->suid = suid->Value();
			}
		}
		next = next->NextSiblingElement();
	}
	next = user_element->FirstChildElement()->FirstChildElement();
	while (next != NULL) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "User") == 0) {
			this->user = value;
		}
		else if (_strcmpi(name, "SessionID") == 0) {
			this->session_id = stoi(value);
		}
		else if (_strcmpi(name, "Address") == 0) {
			this->address = value;
		}
		next = next->NextSiblingElement();
	}
}

Event21::Event21()
{
}

class Event23 {
public:
	int	event_id;
	GTString time_creation;
	int process_id;
	int thread_id;
	int record_id;
	GTString computer;
	GTString suid;
	GTString user;
	int session_id;

	Event23(const char* xml);
	Event23();
};

Event23::Event23(const char* xml) {
	tinyxml2::XMLDocument doc;
	doc.Parse(xml);
	auto root_element = doc.RootElement();
	auto system_element = root_element->FirstChildElement();
	auto next = system_element->FirstChildElement();
	auto user_element = system_element->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;
	while (next) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "EventId") == 0) {
			this->event_id = stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = stoi(tid->Value());
			}
		}
		else if (_strcmpi(name, "Computer") == 0) {
			this->computer = value;
		}
		else if (_strcmpi(name, "Security") == 0) {
			auto suid = next->FindAttribute("UserID");
			if (suid != NULL) {
				this->suid = suid->Value();
			}
		}
		next = next->NextSiblingElement();
	}
	next = user_element->FirstChildElement()->FirstChildElement();
	while (next != NULL) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "User") == 0) {
			this->user = value;
		}
		else if (_strcmpi(name, "SessionID") == 0) {
			this->session_id = stoi(value);
		}

		next = next->NextSiblingElement();
	}
}

Event23::Event23()
{
}


class Event24 {
public:
	int	event_id;
	GTString time_creation;
	int process_id;
	int thread_id;
	int record_id;
	GTString computer;
	GTString suid;
	GTString user;
	int session_id;
	GTString address;
	Event24(const char* xml);
	Event24();
};

Event24::Event24(const char* xml) {
	tinyxml2::XMLDocument doc;
	doc.Parse(xml);
	auto root_element = doc.RootElement();
	auto system_element = root_element->FirstChildElement();
	auto next = system_element->FirstChildElement();
	auto user_element = system_element->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;
	while (next) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "EventId") == 0) {
			this->event_id = stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = stoi(tid->Value());
			}
		}
		else if (_strcmpi(name, "Computer") == 0) {
			this->computer = value;
		}
		else if (_strcmpi(name, "Security") == 0) {
			auto suid = next->FindAttribute("UserID");
			if (suid != NULL) {
				this->suid = suid->Value();
			}
		}
		next = next->NextSiblingElement();
	}
	next = user_element->FirstChildElement()->FirstChildElement();
	while (next != NULL) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "User") == 0) {
			this->user = value;
		}
		else if (_strcmpi(name, "SessionID") == 0) {
			this->session_id = stoi(value);
		}
		else if (_strcmpi(name, "Address") == 0) {
			this->address = value;
		}

		next = next->NextSiblingElement();
	}
}

Event24::Event24()
{
}

class Event25 {
public:
	int	event_id;
	GTString time_creation;
	int process_id;
	int thread_id;
	GTString computer;
	GTString suid;
	GTString user;
	int record_id;
	int session_id;
	GTString address;

	Event25();
	Event25(const char* xml);
};

enum SessionType {
	Remote,
	Local
};

class RDPSession {
public:
	SessionType type;
	int session_id;
	Event21 *start_session;
	Event23 *end_session;
	Event25* start_session_remote;
	Event24* end_session_remote;
	bool is_closed;
	RDPSession(int session_id, Event21 *start);
	RDPSession(int session_id, Event25* start);
	void SetEnd(Event23 *end_session);
	~RDPSession();
};

RDPSession::RDPSession(int session_id, Event21 *start) {
	this->start_session = start;
	this->session_id = session_id;
	this->is_closed = false;
}

RDPSession::RDPSession(int session_id, Event25* start)
{
	this->start_session_remote = start;
	this->session_id = session_id;
	this->is_closed = false;
}

void RDPSession::SetEnd(Event23 *end_session) {
	this->end_session = end_session;
}

RDPSession::~RDPSession() {
	if (start_session != NULL) {
		delete start_session;
	}

	if (end_session != NULL) {
		delete end_session;
	}

	if (start_session_remote != NULL) {
		delete start_session_remote;
	}

	if (end_session_remote != NULL) {
		delete end_session_remote;
	}
}


DWORD RDPProcess(Evt* evt, PVOID data) {
	auto xml = StringUtils::ws2s(evt->GetXml().c_str());
	tinyxml2::XMLDocument doc;
	auto error = doc.Parse(xml.c_str());
	auto root = doc.RootElement();
	auto system = root->FirstChildElement();
	auto &set = *(std::vector<RDPSession*>*)data;
	tinyxml2::XMLElement* child_system_next = system->FirstChildElement();
	tinyxml2::XMLElement* userdata_next = system->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;

	while (child_system_next) {
		value = (char*)child_system_next->GetText();
		name = (char*)child_system_next->Value();
		if (_strcmpi(name, "EventId") == 0) {
			auto event_id = stoi(value);
			Event21 *evt_start = NULL;
			Event23* evt_end = NULL;
			Event25* evt_remote_start = NULL;
			Event24* evt_remote_end = NULL;
			if (event_id == 21) {
				evt_start = new Event21(xml.c_str());
				RDPSession *session = new RDPSession(evt_start->session_id, evt_start);
				session->is_closed = false;
				session->type = Local;
				set.push_back(session);
				break;
			}

			if (event_id == 23) {
				evt_end = new Event23(xml.c_str());
				for (int i = set.size()-1; i >= 0;i--) {
					auto session = set[i];
					if (session->session_id == evt_end->session_id && session->is_closed == false && session->type == Local) {
						session->end_session = evt_end;
						session->is_closed = true;
						break;
					}
				}

			}

			if (event_id == 25) {
				evt_remote_start = new Event25(xml.c_str());
				RDPSession* session = new RDPSession(evt_remote_start->session_id, evt_remote_start);
				session->is_closed = false;
				session->type = Remote;
				set.push_back(session);
			}

			if (event_id == 24) {
				evt_remote_end = new Event24(xml.c_str());
				for (int i = set.size() - 1; i >= 0; i--) {
					auto session = set[i];
					if (session->session_id == evt_remote_end->session_id && session->is_closed == false && session->type == Remote) {
						session->end_session_remote = evt_remote_end;
						session->is_closed = true;
						break;
					}
				}

			}
		}
		child_system_next = child_system_next->NextSiblingElement();
	}

	return 0;
}

GTString ConvertSectoDay(INT64 n) {
	int day = n / (24 * 3600);

	n = n % (24 * 3600);
	int hour = n / 3600;

	n %= 3600;
	int minutes = n / 60;

	n %= 60;
	int seconds = n;
	std::stringstream buffer;
	if (day == 0 && hour == 0 && minutes == 0) {
		buffer << seconds << "s";
	}
	else if (day == 0 && hour == 0) {
		buffer << minutes << "m" << " " << seconds << "s";
	}
	else if (day == 0) {
		buffer << hour
			<< "h " << minutes << "m" << " " << seconds << "s";
	}
	else {
		buffer << day << "d" << " " << hour
			<< "h " << minutes << "m" << " " << seconds << "s";
	}
	return buffer.str();
}

ResultSet* RDPSessions::ModuleRun() {
	EvtInfo info;
	EvtFilter filter;
	filter.ids = L"21,23,24,25";
	filter.logName = L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	std::vector<RDPSession*> result;
	info.EnumEventLogs(filter, RDPProcess, &result, false);
	ResultSet* res = new ResultSet();
	for (int index = result.size()-1; index >= 0; index--) {
		if (result[index]->type == Local) {
			res->PushDictOrdered("User", result[index]->start_session->user);
			auto t1 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->start_session->time_creation.c_str()));
			res->PushDictOrdered("Start", StringUtils::ws2s(t1.String()));
			INT64 count = -1;
			if (result[index]->end_session != NULL) {
				auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->end_session->time_creation.c_str()));
				res->PushDictOrdered("End", StringUtils::ws2s(t2.String()));
				count = t2 - t1;
			}
			else {
				res->PushDictOrdered("End", "online or missing log");
			}
			if (count != -1) {
				res->PushDictOrdered("Duration", ConvertSectoDay(count / 1000));
			}
			else {
				res->PushDictOrdered("Duration", "...");
			}
			res->PushDictOrdered("Computer", result[index]->start_session->computer);
			res->PushDictOrdered("Address", result[index]->start_session->address);
			res->PushDictOrdered("SessionId", std::to_string(result[index]->session_id));
			res->PushDictOrdered("RecordId", std::to_string(result[index]->start_session->record_id));
		}
		else if (result[index]->type == Remote) {
			res->PushDictOrdered("User", result[index]->start_session_remote->user);
			auto t1 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->start_session_remote->time_creation.c_str()));
			res->PushDictOrdered("Start", StringUtils::ws2s(t1.String()));
			INT64 count = -1;
			if (result[index]->end_session_remote != NULL) {
				auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->end_session_remote->time_creation.c_str()));
				res->PushDictOrdered("End", StringUtils::ws2s(t2.String()));
				count = t2 - t1;
			}
			else {
				res->PushDictOrdered("End", "online or missing log");
			}
			if (count != -1) {
				res->PushDictOrdered("Duration", ConvertSectoDay(count / 1000));
			}
			else {
				res->PushDictOrdered("Duration", "...");
			}
			res->PushDictOrdered("Computer", result[index]->start_session_remote->computer);
			res->PushDictOrdered("Address", result[index]->start_session_remote->address);
			res->PushDictOrdered("SessionId", std::to_string(result[index]->session_id));
			res->PushDictOrdered("RecordId", std::to_string(result[index]->start_session_remote->record_id));
		}
		//res->PushDictOrdered("Index", std::to_string(index));
	}

	for (auto session : result) {
		delete session;
	}
	res->SetType(DICT);
	return res;
}

Event25::Event25()
{
}

Event25::Event25(const char* xml) {
	tinyxml2::XMLDocument doc;
	doc.Parse(xml);
	auto root_element = doc.RootElement();
	auto system_element = root_element->FirstChildElement();
	auto next = system_element->FirstChildElement();
	auto user_element = system_element->NextSiblingElement();
	char* value = NULL;
	char* name = NULL;
	while (next) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "EventId") == 0) {
			this->event_id = stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = stoi(tid->Value());
			}
		}
		else if (_strcmpi(name, "Computer") == 0) {
			this->computer = value;
		}
		else if (_strcmpi(name, "Security") == 0) {
			auto suid = next->FindAttribute("UserID");
			if (suid != NULL) {
				this->suid = suid->Value();
			}
		}
		next = next->NextSiblingElement();
	}
	next = user_element->FirstChildElement()->FirstChildElement();
	while (next != NULL) {
		value = (char*)next->GetText();
		name = (char*)next->Value();

		if (_strcmpi(name, "User") == 0) {
			this->user = value;
		}
		else if (_strcmpi(name, "SessionID") == 0) {
			this->session_id = stoi(value);
		}
		else if (_strcmpi(name, "Address") == 0) {
			this->address = value;
		}
		next = next->NextSiblingElement();
	}
}
