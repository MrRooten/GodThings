#pragma once

#include "public.h"
#include <iphlpapi.h>
#include <stdio.h>
#include <vector>
#include <tcpmib.h>
#include <string>
#include "utils.h"
#pragma comment(lib, "Iphlpapi.lib")
class Connection {
public:
	enum Type{
		IPV4,
		IPV6
	};
	Type ipType;
	IN6_ADDR localIPv6;
	IN_ADDR localIPv4;
	IN6_ADDR remoteIPv6;
	IN_ADDR remoteIPv4;
	DWORD localPort;
	DWORD remotePort;
	DWORD State;
	DWORD owningPid;

	std::wstring GetLocalIPAsString();

	std::wstring GetRemoteIPAsString();

	std::wstring GetStateAsString();
};

class TCPManager {
public:
	std::vector<Connection*> connections;
	DWORD SetTCPConnection();
	VOID UpdateTCPConnections();
	~TCPManager();
};