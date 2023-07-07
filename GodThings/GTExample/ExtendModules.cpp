#include "tinyxml2.h"
#include "ExtendModules.h"
#include "RegistryUtils.h"
#include "EvtInfo.h"
#include <vector>
#include <iostream>
#include <chrono>
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
	result->PushDictOrdered("LastShutdown", StringUtils::ws2s(gTime.String_utc_to_local()));
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
			result->PushDictOrdered("time", StringUtils::ws2s(time.String_utc_to_local()));
			result->PushDictOrdered("exe", StringUtils::ws2s(name));
			result->PushDictOrdered("sid", "["+StringUtils::ws2s(key)+"]");
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
		result->PushDictOrdered("exec", StringUtils::ws2s(exec.String_utc_to_local()));
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
	ResultSet* result = new ResultSet();
	auto providers = SecurityProvider::ListProviders();
	for (auto& provider : providers) {
		result->PushDictOrdered("Name", StringUtils::ws2s(provider.GetName()));
		result->PushDictOrdered("Comment", StringUtils::ws2s(provider.GetComment()));
		
	}
	result->SetType(DICT);
	return result;
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
			this->event_id = std::stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = std::stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = std::stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = std::stoi(tid->Value());
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
			this->session_id = std::stoi(value);
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
			this->event_id = std::stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = std::stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = std::stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = std::stoi(tid->Value());
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
			this->session_id = std::stoi(value);
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
			this->event_id = std::stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = std::stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = std::stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = std::stoi(tid->Value());
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
			this->session_id = std::stoi(value);
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

enum CloseType {
	CloseConn,
	Logoff
};

enum SessionType {
	Relogin,
	Login
};
class RDPSession {
public:
	CloseType type;
	SessionType s_type;
	int session_id;
	Event21 *login_event;
	Event23 *logoff_event;
	Event25* relogin_event;
	Event24* close_conn_event;
	bool is_closed;
	RDPSession(int session_id, Event21 *start);
	RDPSession(int session_id, Event25* start);
	void SetEnd(Event23 *logoff_event);
	~RDPSession();
};

RDPSession::RDPSession(int session_id, Event21 *start) {
	this->login_event = start;
	this->session_id = session_id;
	this->is_closed = false;
}

RDPSession::RDPSession(int session_id, Event25* start)
{
	this->relogin_event = start;
	this->session_id = session_id;
	this->is_closed = false;
}

void RDPSession::SetEnd(Event23 *logoff_event) {
	this->logoff_event = logoff_event;
}

RDPSession::~RDPSession() {
	if (login_event != NULL) {
		delete login_event;
	}

	if (logoff_event != NULL) {
		delete logoff_event;
	}

	if (relogin_event != NULL) {
		delete relogin_event;
	}

	if (close_conn_event != NULL) {
		delete close_conn_event;
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
			auto event_id = std::stoi(value);
			Event21 *evt_start = NULL;
			Event23* evt_end = NULL;
			Event25* evt_remote_start = NULL;
			Event24* evt_remote_end = NULL;
			if (event_id == 21) {
				evt_start = new Event21(xml.c_str());
				RDPSession *session = new RDPSession(evt_start->session_id, evt_start);
				session->is_closed = false;
				session->s_type = Login;
				set.push_back(session);
				break;
			}

			if (event_id == 23) {
				evt_end = new Event23(xml.c_str());
				for (int i = set.size()-1; i >= 0;i--) {
					auto session = set[i];
					if (session->session_id == evt_end->session_id && session->is_closed == false) {
						session->type = Logoff;
						session->logoff_event = evt_end;
						session->is_closed = true;
						break;
					}
				}

			}

			if (event_id == 25) {
				evt_remote_start = new Event25(xml.c_str());
				RDPSession* session = new RDPSession(evt_remote_start->session_id, evt_remote_start);
				session->is_closed = false;
				session->s_type = Relogin;
				set.push_back(session);
			}

			if (event_id == 24) {
				evt_remote_end = new Event24(xml.c_str());
				for (int i = set.size() - 1; i >= 0; i--) {
					auto session = set[i];
					if (session->session_id == evt_remote_end->session_id && session->is_closed == false) {
						session->type = CloseConn;
						session->close_conn_event = evt_remote_end;
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
	INT64 seconds = n;
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
	if (this->args.contains("path")) {
		info.EnumEventLogs(filter, RDPProcess, &result, false, (wchar_t*)StringUtils::s2ws(this->args["path"]).c_str());
	}
	else {
		info.EnumEventLogs(filter, RDPProcess, &result, false, NULL);
	}
	ResultSet* res = new ResultSet();
	for (int index = (int)result.size()-1; index >= 0; index--) {
		if (result[index]->s_type == Login) {
			res->PushDictOrdered("User", result[index]->login_event->user);
			auto t1 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->login_event->time_creation.c_str()));
			res->PushDictOrdered("Start", StringUtils::ws2s(t1.String_utc_to_local()));
			INT64 count = -1;
			if (result[index]->type == CloseConn) {
				if (result[index]->close_conn_event != NULL) {
					auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->close_conn_event->time_creation.c_str()));
					res->PushDictOrdered("End", StringUtils::ws2s(t2.String_utc_to_local()));
					count = t2 - t1;
				}
				else {
					res->PushDictOrdered("End", "online or missing log");
				}
			}
			else {
				if (result[index]->logoff_event != NULL) {
					auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->logoff_event->time_creation.c_str()));
					res->PushDictOrdered("End", StringUtils::ws2s(t2.String_utc_to_local()));
					count = t2 - t1;
				}
				else {
					res->PushDictOrdered("End", "online or log is missing");
				}
			}

			if (count != -1) {
				res->PushDictOrdered("Duration", ConvertSectoDay(count / 1000));
			}
			else {
				res->PushDictOrdered("Duration", "...");
			}
			res->PushDictOrdered("Computer", result[index]->login_event->computer);
			res->PushDictOrdered("Address", result[index]->login_event->address);
			res->PushDictOrdered("RecordId", std::to_string(result[index]->login_event->record_id));
			if (result[index]->type == Logoff) {
				res->PushDictOrdered("ExitType", "Logoff");
			}
			else if (result[index]->logoff_event == NULL && result[index]->close_conn_event == NULL) {
				if (index == result.size() - 1) {
					res->PushDictOrdered("ExitType", "NotExit?");
				}
				else {
					res->PushDictOrdered("ExitType", "ForceShutdown?");
				}
			}
			else {
				res->PushDictOrdered("ExitType", "CloseConnection");
			}
		}
		else if (result[index]->s_type == Relogin) {
			res->PushDictOrdered("User", result[index]->relogin_event->user);
			auto t1 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->relogin_event->time_creation.c_str()));
			res->PushDictOrdered("Start", StringUtils::ws2s(t1.String_utc_to_local()));
			INT64 count = -1;
			if (result[index]->type == CloseConn) {
				if (result[index]->close_conn_event != NULL) {
					auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->close_conn_event->time_creation.c_str()));
					res->PushDictOrdered("End", StringUtils::ws2s(t2.String_utc_to_local()));
					count = t2 - t1;
				}
				else {
					res->PushDictOrdered("End", "online or missing log");
				}
			}
			else {
				if (result[index]->logoff_event != NULL) {
					auto t2 = GTTime::FromISO8601(StringUtils::s2ws(result[index]->logoff_event->time_creation.c_str()));
					res->PushDictOrdered("End", StringUtils::ws2s(t2.String_utc_to_local()));
					count = t2 - t1;
				}
				else {
					res->PushDictOrdered("End", "online or log is missing");
				}
			}
			
			if (count != -1) {
				res->PushDictOrdered("Duration", ConvertSectoDay(count / 1000));
			}
			else {
				res->PushDictOrdered("Duration", "...");
			}
			res->PushDictOrdered("Computer", result[index]->relogin_event->computer);
			res->PushDictOrdered("Address", result[index]->relogin_event->address);
			res->PushDictOrdered("RecordId", std::to_string(result[index]->relogin_event->record_id));
			if (result[index]->type == Logoff) {
				res->PushDictOrdered("ExitType", "Logoff");
			}
			else if (result[index]->logoff_event == NULL && result[index]->close_conn_event == NULL) {
				if (index == result.size() - 1) {
					res->PushDictOrdered("ExitType", "NotExit?");
				}
				else {
					res->PushDictOrdered("ExitType", "ForceShutdown?");
				}
			}
			else {
				res->PushDictOrdered("ExitType", "CloseConnection");
			}
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
			this->event_id = std::stoi(value);
		}
		else if (_strcmpi(name, "TimeCreated") == 0) {
			auto attr = next->FindAttribute("SystemTime");
			if (attr != NULL) {
				this->time_creation = attr->Value();
			}
		}
		else if (_strcmpi(name, "EventRecordId") == 0) {
			this->record_id = std::stoi(value);
		}
		else if (_strcmpi(name, "Execution") == 0) {
			auto pid = next->FindAttribute("ProcessID");
			auto tid = next->FindAttribute("ThreadID");
			if (pid != NULL) {
				this->process_id = std::stoi(pid->Value());
			}

			if (tid != NULL) {
				this->thread_id = std::stoi(tid->Value());
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
			this->session_id = std::stoi(value);
		}
		else if (_strcmpi(name, "Address") == 0) {
			this->address = value;
		}
		next = next->NextSiblingElement();
	}
}

class ClientSession {
public:
	GTString targetIP;
	GTString usernameHash;
	GTWString startTime;
	GTWString closeTime;
	GTString closeReason;
	GTString domain;

	ClientSession(EventLogInst& inst);
	DWORD PushEvent(EventLogInst& inst);
};

DWORD RDPClient(Evt* evt, PVOID data) {
	EventLogInst inst;
	inst.Parse(StringUtils::ws2s(evt->GetXml()).c_str());
	auto id = (DWORD)atoi(inst.Fetch("Event.System.EventID.EventID"));
	auto result = (std::vector<ClientSession>*)data;
	if (id == 1024) {
		result->push_back(ClientSession(inst));
	}
	else {
		if (result->size() == 0) {
			return 0;
		}
		result->at(result->size() - 1).PushEvent(inst);
	}

	return 0;
}

RDPClientSess::RDPClientSess() {
	this->Name = L"RDPClientSess";
	this->Path = L"EventLog";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Enum Sessions logs";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

const char* rdp_close_reason(std::string &reason) {
	if (reason.size() == 0) {
		return NULL;
	}
	auto id = std::stoi(reason);
	if (id == 0) {
		return "No error";
	}
	else if (id == 1) {
		return "User-initiated client disconnect";
	}
	else if (id == 2) {
		return "User-initiated client logoff";
	}
	else if (id == 3) {
		return "Your Remote Desktop Services session has ended";
	}
	else if (id == 263) {
		return "The remote session was disconnected because the client prematurely ended the licensing protocol";
	}
	else if (id == 516) {
		return "Remote Desktop can't connect to the remote computer";
	}
	else if (id == 2308) {
		return "Your Remote Desktop Services session has ended";
	}
	else {
		return NULL;
	}
}

std::map<GTString, GTWString> _get_hash_username() {
	std::wstring alluserAssist = L"HKEY_USERS";
	RegistryUtils allUserAssistReg(alluserAssist);
	std::map<GTString, GTWString> result;
	auto users = allUserAssistReg.ListSubKeys();
	for (auto& user : users) {
		if (user == L".DEFAULT") {
			continue;
		}

		//wprintf(L"%s %s\n", user.c_str(),ConvertSidToUsername(user.c_str()));
		std::wstring servers = L"HKEY_USERS\\" + user + L"\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers\\";
		RegistryUtils userAssistReg(servers);
		auto subs = userAssistReg.ListSubKeys();
		for (auto& sub : subs) {
			std::wstring key = servers + sub;
			RegistryUtils utils(key);
			auto buffer = RegistryUtils::GetValueStatic(key.c_str(), L"UsernameHint");
			GTWString wbuffer = (WCHAR*)buffer.c_str();
			auto username = wbuffer.substr(wbuffer.find(L'\\')+1);
			auto sha256 = Sha256((PBYTE)username.data(), username.size() * (sizeof WCHAR));
			if (sha256.size() != 0) {
				auto base64 = Base64Encode((PBYTE)sha256.data(), sha256.size()) + "-";
				result[base64] = username;
			}
			auto sha1 = Sha1((PBYTE)username.data(), username.size() * (sizeof WCHAR));
			if (sha1.size() != 0) {
				auto base64_sha1 = Base64Encode((PBYTE)sha1.data(), sha1.size()) + "-";
				result[base64_sha1] = username;
			}
		}
	}


	return result;
}

ResultSet* RDPClientSess::ModuleRun() {
	auto m = _get_hash_username();
	EvtInfo info;
	EvtFilter filter;
	ResultSet* set = new ResultSet();
	filter.logName = L"Microsoft-Windows-TerminalServices-RDPClient/Operational";
	filter.ids = L"1024,1026,1027,1029";
	std::vector<ClientSession> result;
	if (this->args.contains("path")) {
		info.EnumEventLogs(filter, RDPClient, &result, false, (wchar_t*)StringUtils::s2ws(this->args["path"]).c_str());
	}
	else {
		info.EnumEventLogs(filter, RDPClient, &result, false, NULL);
	}

	std::reverse(result.begin(), result.end());
	for (auto& client : result) {
		auto start = GTTime::FromISO8601(client.startTime);
		set->PushDictOrdered("start", StringUtils::ws2s(start.String_utc_to_local()));
		auto end = GTTime::FromISO8601(client.closeTime);
		auto count = end - start;
		set->PushDictOrdered("end", StringUtils::ws2s(end.String_utc_to_local()));
		if (count >= 0) {
			set->PushDictOrdered("duration", ConvertSectoDay(count / 1000));
		}
		else {
			set->PushDictOrdered("duration", "...");
		}
		
		set->PushDictOrdered("remote", client.targetIP);
		set->PushDictOrdered("domain", client.domain);
		auto reason = rdp_close_reason(client.closeReason);
		

		if (m.contains(client.usernameHash)) {
			set->PushDictOrdered("username", StringUtils::ws2s(m[client.usernameHash]));
		}
		else if (client.usernameHash.size() != 0) {
			set->PushDictOrdered("username", "base64(sha256):"+ client.usernameHash);
		}
		else {
			set->PushDictOrdered("username", "");
		}

		if (reason != NULL) {
			set->PushDictOrdered("reason", reason);
		}
		else {
			set->PushDictOrdered("reason", client.closeReason);
		}
		
		
	}
	set->SetType(DICT);
	return set;
}

ClientSession::ClientSession(EventLogInst& inst) {
	this->startTime = StringUtils::s2ws(inst.Fetch("Event.System.TimeCreated.SystemTime"));
	this->targetIP = inst.FetchData("Value");
}

DWORD ClientSession::PushEvent(EventLogInst& inst) {
	auto id = (DWORD)atoi(inst.Fetch("Event.System.EventId.EventId"));
	if (id == 1026) {
		this->closeTime = StringUtils::s2ws(inst.Fetch("Event.System.TimeCreated.SystemTime"));
		this->closeReason = inst.FetchData("Value");
	}
	else if (id == 1027) {
		this->domain = inst.FetchData("DomainName");
	}
	else if (id == 1029) {
		this->usernameHash = inst.FetchData("TraceMessage");
	}
	return 0;
}

LoadedFiles::LoadedFiles() {
	this->Name = L"LoadedFiles";
	this->Path = L"System";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get Loaded Files group by process";
	this->RunType = ModuleNotAuto;
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
#include <signal.h>
void SignalHandler(int signal)
{

}
#include <VersionHelpers.h>
#include "MagicUtils.h"
#include "FileUtils.h"
ResultSet* LoadedFiles::ModuleRun() {
	//ResultSet* result = new ResultSet();
	std::vector<UINT32> pids;
	if (!this->args.contains("pid")) {
		this->args["pid"] = "*";
	}

	if (this->args["pid"] == "*") {
		auto mgr = ProcessManager::GetMgr();
		mgr->SetAllProcesses();
		for (auto pid : mgr->processesMap) {
			pids.push_back(pid.first);
		}
	}
	else {
		auto pid = stoi(this->args["pid"]);
		pids.push_back(pid);
	}
	typedef void (*SignalHandlerPointer)(int);

	SignalHandlerPointer previousHandler;
	previousHandler = signal(SIGSEGV, SignalHandler);
	//if (IsWindows8OrGreater()) {
		
	if (false) { //Test which is better, always use the SystemInfo::GetSystemLoadedFiles
		FileMagic* magic = FileMagic::NewInstance(".\\magic.mgc");
		for (auto pid : pids) {
			auto mgr = ProcessManager::GetMgr();
			auto p = mgr->processesMap[pid];
			try {
				auto files = p->GetLoadedFiles();
				wprintf(L"%s:%d\n", p->GetProcessName().c_str(), pid);
				for (auto& file : files) {
					auto dos_path = TryNTPathToDOSPath(file.second.c_str());
					const CHAR* f_type = NULL;
					if (magic != NULL) {
						f_type = magic->FileFile(StringUtils::ws2s(dos_path).c_str());
					}
					else {
						f_type = "";
					}
					
					wprintf(L"\t%s: '%s' \n\tType: '%s'\n", file.first.c_str(), file.second.c_str(), StringUtils::s2ws(f_type).c_str());
				}
				delete p;
			}
			catch (char* _) {

			}

		}
	}
	else {
		SystemInfo info;
		auto all_files = info.GetSystemLoadedFiles();
		auto mgr = ProcessManager::GetMgr();
		int i = 0;
		FileMagic* magic = FileMagic::NewInstance(".\\magic.mgc");
		for (auto pid : pids) {
			auto p = mgr->processesMap[pid];
			auto &files = all_files[pid];
			wprintf(L"%s:%d\n", p->GetProcessName().c_str(), pid);
			for (auto& file : files) {
				auto dos_path = TryNTPathToDOSPath(file.second.c_str());
				const CHAR* f_type = NULL;
				if (magic != NULL) {
					f_type = magic->FileFile(StringUtils::ws2s(dos_path).c_str());
				}
				else {
					f_type = "";
				}
				if (file.first == SysDirectory) {
					wprintf(L"\tDirectory: '%s' \n\tType: '%s'\n", dos_path.c_str(), StringUtils::s2ws(f_type).c_str());
				}
				else if (file.first == SysFile) {
					wprintf(L"\tFile: '%s' \n\tType: '%s'\n", dos_path.c_str(), StringUtils::s2ws(f_type).c_str());
				}
				else if (file.first == SysKey) {
					wprintf(L"\tKey: '%s'\n", file.second.c_str());
				}
			}
		}
	}
	
	return nullptr;
}

File::File() {
	this->Name = L"File";
	this->Path = L"File";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get File Type of specified file";
	this->RunType = ModuleNeedArgs;
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

int IsWhat(const std::string& path)
{
	DWORD fileAttributes = ::GetFileAttributesA(path.c_str());

	if (fileAttributes == FILE_ATTRIBUTE_DIRECTORY && (fileAttributes != INVALID_FILE_ATTRIBUTES)) {
		return -1;
	}


	return 1;
}

ResultSet* File::ModuleRun() {
	auto result = new ResultSet();
	if (!this->args.contains("file")) {
		result->SetErrorMessage("Must set a pid to get dll information: File.File 'file=${file}'");
		LOG_INFO(L"Must set a pid to get dll information: File.File 'file=${file}'");
	}

	auto& file = args["file"];
	FileMagic* magic = FileMagic::NewInstance(".\\magic.mgc");
	if (magic == NULL) {
		LOG_ERROR_REASON(L"Error to new .\\magic.mgc");
		return NULL;
	}

	if (file.ends_with("\\")) {
		file = file.substr(0, file.size() - 1);
	}
	auto ret = IsWhat(file);
	if (ret == -1) { //If is directory
		GTDir dir(StringUtils::s2ws(file).c_str());
		auto files = dir.ListFiles();
		for (auto& _tmp_file : files) {
			auto start = std::chrono::high_resolution_clock::now();
			auto _tmp_file_a = StringUtils::ws2s(_tmp_file);
			if (_tmp_file_a == "." || _tmp_file_a == "..") {
				continue;
			}
			auto path = file + "\\" + _tmp_file_a;
			const char* f = magic->FileFile(path.c_str());
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = duration_cast<std::chrono::microseconds>(end - start);
			if (f == NULL) {
				auto error = magic->GetErrorString();
				LOG_ERROR(StringUtils::s2ws(error).c_str());
				continue;
			}

			result->PushDictOrdered("Path", path.c_str());
			result->PushDictOrdered("File", f);
		}
	}
	else if (ret == 1) { //If is normal file
		auto start = std::chrono::high_resolution_clock::now();
		const char* f = magic->FileFile(file.c_str());
		auto end = std::chrono::high_resolution_clock::now();
		auto duration = duration_cast<std::chrono::microseconds>(end - start);
		if (f == NULL) {
			auto error = magic->GetErrorString();
			LOG_ERROR(StringUtils::s2ws(error).c_str());
			return NULL;
		}

		result->PushDictOrdered("Path", file.c_str());
		result->PushDictOrdered("File", f);
	}
	else {
		LOG_ERROR_REASON(L"");
		return NULL;
	}
	
	
	result->SetType(DICT);
	return result;
}
#include "ObjectInfo.h"
ProcessHandle::ProcessHandle() {
	this->Name = L"Handle";
	this->Path = L"Process";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get File Type of specified file";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}

ResultSet* ProcessHandle::ModuleRun() {
	std::vector<UINT32> pids;
	ResultSet* result = new ResultSet();
	if ((!this->args.contains("pid")) && (!this->args.contains("name"))) {
		result->SetErrorMessage("Error must set pid=${pid} or name=${process}, name can be substr of origin process name");
		result->SetType(ResultType::ERROR_MESSAGE);
		return result;
	}
	auto mgr = ProcessManager::GetMgr();
	mgr->SetAllProcesses();
	if (this->args["pid"] == "*") {
		for (auto pid : mgr->processesMap) {
			pids.push_back(pid.first);
		}
	}
	else {
		auto pid = stoi(this->args["pid"]);
		pids.push_back(pid);
	}

	if (this->args.contains("name")) {
		auto& name = this->args["name"];
		for (auto& proc : mgr->processesMap) {
			if (proc.second->GetProcessName().find(StringUtils::s2ws(name))) {
				pids.push_back(proc.first);
			}
		}
	}

	std::set<DWORD> s_pids(pids.begin(), pids.end());
	SystemInfo info;
	info.IterateSystemHandle(
		[&result, &mgr, &s_pids](auto pid, auto hObject) {
			auto& map = mgr->processesMap;
			if (s_pids.contains(pid) == false || map.contains(pid) == false) {
				return;
			}
			auto a = GetFileType(hObject);
			if (a == FILE_TYPE_PIPE || a == FILE_TYPE_CHAR) {
				return;
			}

			Process* process = map[pid];
			auto name = process->GetProcessName();
			GTWString objName = ObjectInfo::GetObjectName(hObject);
			auto objType = ObjectInfo::GetTypeName(hObject);
			wprintf(L"\t%s: %s\n", objType.c_str(), objName.c_str());
		}, s_pids
	);


	return result;
}

StaticInfo::StaticInfo() {
	this->Name = L"StaticInfo";
	this->Path = L"WMI";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
#include "WmiUtils.h"
ResultSet* StaticInfo::ModuleRun() {
	ResultSet* result = new ResultSet();
	WmiTaker taker;
	auto r1 = taker.take(L"SELECT * FROM Win32_Processor");
	auto r2 = taker.take(L"SELECT * FROM Win32_ComputerSystem");
	auto r3 = taker.take(L"SELECT * FROM Win32_NetworkAdapterConfiguration");
	auto &v = r1[0];
	auto& v2 = r2[0];
	std::wstring n = L"abc";
	result->PushDictOrdered("CPUName", StringUtils::ws2s(std::get<std::wstring>(v[L"Caption"])));
	result->PushDictOrdered("Domain", StringUtils::ws2s(std::get<std::wstring>(v2[L"Domain"])));
	result->PushDictOrdered("Model", StringUtils::ws2s(std::get<std::wstring>(v2[L"Model"])));
	result->PushDictOrdered("Name", StringUtils::ws2s(std::get<std::wstring>(v2[L"Name"])));
	result->PushDictOrdered("PrimaryOwnerName", StringUtils::ws2s(std::get<std::wstring>(v2[L"PrimaryOwnerName"])));
	result->PushDictOrdered("TotalPhysicalMemory", StringUtils::ws2s(std::get<std::wstring>(v2[L"TotalPhysicalMemory"])));
	result->SetType(DICT);
	return result;
}

NetInterfaces::NetInterfaces() {
	this->Name = L"NetInterfaces";
	this->Path = L"Network";
	this->Type = L"Extender";
	this->Class = L"GetInfo";
	this->Description = L"Get Interface of system";
	auto mgr = ModuleMgr::GetMgr();
	mgr->RegisterModule(this);
}
#include "Network.h"
ResultSet* NetInterfaces::ModuleRun() {
	auto result = new ResultSet();
	auto interfaces = NetInterface::GetInterfaces();
	for (auto& i : interfaces) {
		result->PushDictOrdered("Name", i.GetName());
		result->PushDictOrdered("IpAddr", i.GetIpAddress());
		result->PushDictOrdered("Mask", i.GetMask());
		result->PushDictOrdered("Gateway", i.GetGateway());
		result->PushDictOrdered("Type", i.GetType());
		result->PushDictOrdered("Description", i.GetDescription());
	}
	result->SetType(DICT);
	return result;
}
