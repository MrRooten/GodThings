#pragma once

#include "public.h"
#include <iphlpapi.h>
#include <stdio.h>
#include <vector>
#include <tcpmib.h>
#include <string>
#include "utils.h"
#include <map>
#pragma comment(lib, "Iphlpapi.lib")
typedef struct _MIB_UDP6ROW_OWNER_MODULE {
	UCHAR           ucLocalAddr[16];
	DWORD           dwLocalScopeId;
	DWORD           dwLocalPort;
	DWORD           dwOwningPid;
	LARGE_INTEGER   liCreateTimestamp;
	union {
		struct {
			int     SpecificPortBind : 1;
		};
		int         dwFlags;
	};
	ULONGLONG       OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDP6ROW_OWNER_MODULE, * PMIB_UDP6ROW_OWNER_MODULE;

typedef struct _MIB_UDP6TABLE_OWNER_MODULE
{
	DWORD                    dwNumEntries;
	MIB_UDP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_MODULE, * PMIB_UDP6TABLE_OWNER_MODULE;

enum class Protocol {
	TCP,
	UDP
};

enum class IPType {
	IPV4,
	IPV6
};

class Connection {
public:
	IPType ipType;
	IN6_ADDR localIPv6;
	IN_ADDR localIPv4;
	IN6_ADDR remoteIPv6;
	IN_ADDR remoteIPv4;
	DWORD localPort;
	DWORD remotePort;
	DWORD State;	
	DWORD owningPid;
	Protocol protocol;
	std::wstring GetLocalIPAsString();

	std::wstring GetRemoteIPAsString();

	std::wstring GetStateAsString();

	friend bool operator==(const Connection& conn1, const Connection& conn2);
};

class NetworkManager {
	void ClearConnection();
public:
	std::vector<Connection*> connections;
	DWORD SetTCPConnection();
	DWORD SetUDPConnection();
	std::vector<Connection*> GetConnectionsByPid(DWORD pid);
	std::vector<Connection*> GetUDPConnections();
	std::vector<Connection*> GetTCPConnections();
	std::vector<Connection*> GetAllConnections();
	VOID UpdateTCPConnections();
	~NetworkManager();
};

class Interface {
	GTWString DefaultGateway;
	GTWString Domain;
	bool EnableDhcp;
	GTWString Hostname;
	GTWString IPAddress;
	GTWString IPEnableRouter;
	GTWString SubnetMask;
	GTWString DhcpDefaultGateway;
	GTWString DhcpIPAddress;
	GTWString DhcpNameServer;
public:
	Interface(wchar_t* guid);
};
#include <map>



class DnsCache {
	std::map<GTString, GTString> _cache;
	static DnsCache* single;
public:
	static DnsCache* GetInstance();
	void Update();
	LPCSTR GetDomain(const char* ip);
};