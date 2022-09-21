#include "Network.h"
#include "utils.h"
#include "ntapi.h"
#include "NetworkUtils.h"
#include <Shlwapi.h>
typedef struct _MIB_TCP6ROW2 {
	IN6_ADDR                     LocalAddr;
	DWORD                        dwLocalScopeId;
	DWORD                        dwLocalPort;
	IN6_ADDR                     RemoteAddr;
	DWORD                        dwRemoteScopeId;
	DWORD                        dwRemotePort;
	MIB_TCP_STATE                State;
	DWORD                        dwOwningPid;
	TCP_CONNECTION_OFFLOAD_STATE dwOffloadState;
} MIB_TCP6ROW2, * PMIB_TCP6ROW2;
typedef struct _MIB_TCP6TABLE2 {
	DWORD        dwNumEntries;
	MIB_TCP6ROW2 table[ANY_SIZE];
} MIB_TCP6TABLE2, * PMIB_TCP6TABLE2;
typedef ULONG (*pGetTcp6Table2)(
	PMIB_TCP6TABLE2 TcpTable,
	PULONG         SizePointer,
	BOOL           Order
);
void NetworkManager::ClearConnection() {
	for (auto& conn : this->connections) {
		delete conn;
	}
	this->connections.clear();
	std::vector<Connection*>().swap(this->connections);
}
DWORD NetworkManager::SetTCPConnection() {
	PMIB_TCPTABLE2 pTcpTable = NULL;
	PMIB_TCP6TABLE2 pTcp6Table = NULL;
	DWORD size = 1000;
	DWORD status;
	DWORD num;
	pGetTcp6Table2 GetTcp6Table2 = NULL;
	pTcpTable = (PMIB_TCPTABLE2)LocalAlloc(GPTR, size);
	if (pTcpTable == NULL) {
		Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in Alloc Space:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		goto cleanup;
	}
	
	status = GetTcpTable2(pTcpTable, &size, TRUE);
	if (status != NO_ERROR && status != ERROR_INSUFFICIENT_BUFFER) {
		Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in GetTcpTable2:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
		goto cleanup;
	}
	for (int i = 0; i < 8 && status == ERROR_INSUFFICIENT_BUFFER;i++) {
		pTcpTable = (PMIB_TCPTABLE2)LocalReAlloc(pTcpTable, size, GPTR|GMEM_MOVEABLE);
		if (pTcpTable == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in Alloc Space:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			goto cleanup;
		}
		status = GetTcpTable2(pTcpTable, &size, TRUE);
	}


	GetTcp6Table2 = (pGetTcp6Table2)GetAnyProc("Iphlpapi.dll", "GetTcp6Table2");
	if (GetTcp6Table2 != NULL) {
		size = 0x1000;
		pTcp6Table = (PMIB_TCP6TABLE2)LocalAlloc(GPTR, size);
		if (pTcp6Table == NULL) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in Alloc Space:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			goto cleanup;
		}

		status = GetTcp6Table2(pTcp6Table, &size, TRUE);
		if (status != NO_ERROR && status != ERROR_INSUFFICIENT_BUFFER) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in GetTcpTable2:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
			goto cleanup;
		}
		for (int i = 0; i < 8 && status == ERROR_INSUFFICIENT_BUFFER; i++) {
			pTcp6Table = (PMIB_TCP6TABLE2)LocalReAlloc(pTcp6Table, size, GPTR | GMEM_MOVEABLE);
			if (pTcpTable == NULL) {
				Logln(ERROR_LEVEL, L"[%s:%s:%d]:Error in Alloc Space:%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
				goto cleanup;
			}
			status = GetTcp6Table2(pTcp6Table, &size, TRUE);
		}
	}
	this->connections.clear();
	num = pTcpTable->dwNumEntries;
	for (size_t i = 0; i < num; i++) {
		Connection* conn = new Connection();
		if (conn == nullptr) {
			Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not new Connection():%d,%s\n",__FILEW__,__FUNCTIONW__,__LINE__,GetLastError(),GetLastErrorAsString());
			break;
		}
		conn->localIPv4.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
		conn->localPort = pTcpTable->table[i].dwLocalPort;
		conn->remoteIPv4.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
		conn->remotePort = pTcpTable->table[i].dwRemotePort;
		conn->owningPid = pTcpTable->table[i].dwOwningPid;
		conn->State = pTcpTable->table[i].dwState;
		conn->ipType = IPType::IPV4;
		this->connections.push_back(conn);
	}
	if (GetTcp6Table2 != NULL) {
		num = pTcp6Table->dwNumEntries;
		for (size_t i = 0; i < num; i++) {
			Connection* conn = new Connection();
			if (conn == nullptr) {
				Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not new Connection():%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
				break;
			}
			conn->localIPv6 = pTcp6Table->table[i].LocalAddr;
			conn->localPort = pTcp6Table->table[i].dwLocalPort;
			conn->remoteIPv6 = pTcp6Table->table[i].RemoteAddr;
			conn->remotePort = pTcp6Table->table[i].dwRemotePort;
			conn->owningPid = pTcp6Table->table[i].dwOwningPid;
			conn->State = pTcpTable->table[i].dwState;
			conn->ipType = IPType::IPV6;
			this->connections.push_back(conn);
		}
	}
cleanup:
	if (pTcpTable != NULL) {
		LocalFree(pTcpTable);
	}

	if (pTcp6Table != NULL) {
		LocalFree(pTcp6Table);
	}
	return status;
}


DWORD NetworkManager::SetUDPConnection() {
	DWORD tableSize = 0;
	PVOID table = NULL;
	PMIB_UDPTABLE_OWNER_MODULE udp4Table;
	PMIB_UDP6TABLE_OWNER_MODULE udp6Table;
	GetExtendedUdpTable(NULL, &tableSize, FALSE, 2, UDP_TABLE_OWNER_MODULE, 0); //NULL, &tableSize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0
	table = LocalAlloc(GPTR, tableSize);
	if (table == NULL) {
		return GetLastError();
	}

	if (GetExtendedUdpTable(table, &tableSize, FALSE, 2, UDP_TABLE_OWNER_MODULE, 0)!=ERROR_SUCCESS) {
		LocalFree(table);
		return GetLastError();
	}


	udp4Table = (PMIB_UDPTABLE_OWNER_MODULE)table;
	if (udp4Table != NULL) {
		for (DWORD i = 0; i < udp4Table->dwNumEntries; i++) {
			Connection* conn = new Connection();
			if (conn == nullptr) {
				Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not new Connection():%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
				break;
			}
			conn->localIPv4 = NetworkUtils::ConvertDWORDToIN_ADDR(udp4Table->table[i].dwLocalAddr);
			conn->localPort = udp4Table->table[i].dwLocalPort;
			conn->owningPid = udp4Table->table[i].dwOwningPid;
			conn->protocol = Protocol::UDP;
			conn->ipType = IPType::IPV4;
			this->connections.push_back(conn);
		}
	}

	LocalFree(table);
	table = NULL;
	tableSize = 0;
	udp4Table = NULL;

	GetExtendedUdpTable(NULL, &tableSize, FALSE, 23, UDP_TABLE_OWNER_MODULE, 0); //NULL, &tableSize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0
	table = LocalAlloc(GPTR, tableSize);
	if (table == NULL) {
		return GetLastError();
	}

	if (GetExtendedUdpTable(table, &tableSize, FALSE, 23, UDP_TABLE_OWNER_MODULE, 0) != ERROR_SUCCESS) {
		LocalFree(table);
		return GetLastError();
	}


	udp6Table = (PMIB_UDP6TABLE_OWNER_MODULE)table;
	if (udp6Table != NULL) {
		for (DWORD i = 0; i < udp6Table->dwNumEntries; i++) {
			Connection* conn = new Connection();
			if (conn == nullptr) {
				Logln(ERROR_LEVEL, L"[%s:%s:%d]:Can not new Connection():%d,%s\n", __FILEW__, __FUNCTIONW__, __LINE__, GetLastError(), GetLastErrorAsString());
				break;
			}
			conn->localIPv6 = NetworkUtils::ConvertBytesToIN_ADDR6(udp6Table->table[i].ucLocalAddr);
			conn->localPort = udp6Table->table[i].dwLocalPort;
			conn->owningPid = udp6Table->table[i].dwOwningPid;
			conn->protocol = Protocol::UDP;
			conn->ipType = IPType::IPV6;
			this->connections.push_back(conn);
		}
	}
	LocalFree(table);
	return 0;
}

std::vector<Connection*> NetworkManager::GetConnectionsByPid(DWORD pid) {
	this->ClearConnection();
	this->SetTCPConnection();
	this->SetUDPConnection();
	std::vector<Connection*> result;
	for (auto& conn : this->connections) {
		if (conn->owningPid == pid) {
			result.push_back(conn);
		}
	}
	return result;
}

std::vector<Connection*> NetworkManager::GetUDPConnections() {
	this->ClearConnection();
	this->SetUDPConnection();
	return this->connections;
}

std::vector<Connection*> NetworkManager::GetTCPConnections() {
	this->ClearConnection();
	this->SetTCPConnection();
	return this->connections;
}

std::vector<Connection*> NetworkManager::GetAllConnections() {
	this->ClearConnection();
	this->SetTCPConnection();
	this->SetUDPConnection();
	return this->connections;
}

VOID NetworkManager::UpdateTCPConnections() {

}


NetworkManager::~NetworkManager() {
	this->ClearConnection();
}

std::wstring ConvertIP(DWORD ip)
{
	unsigned char a, b, c, d;
	d = ip & 0xFF;
	c = (ip >> 8) & 0xFF;
	b = (ip >> 16) & 0xFF;
	a = (ip >> 24) & 0xFF;

	std::wstring conv;
	WCHAR buffer[40];
	wnsprintfW(buffer, 40, L"%u.%u.%u.%u", d, c, b, a);
	conv = buffer;
	return conv;
}
#include "StringUtils.h"

std::wstring ConvertIPv6(const IN6_ADDR* pAddr) {
	struct in6_addr a;
	memcpy(&a.u, &pAddr->u, sizeof(struct in6_addr));
	char buf[40];
	sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			a.s6_addr[0], a.s6_addr[1], a.s6_addr[2], a.s6_addr[3],
			a.s6_addr[4], a.s6_addr[5], a.s6_addr[6], a.s6_addr[7],
			a.s6_addr[8], a.s6_addr[9], a.s6_addr[10], a.s6_addr[11],
			a.s6_addr[12], a.s6_addr[13], a.s6_addr[14], a.s6_addr[15]);
	return StringUtils::s2ws(buf);

}
std::wstring Connection::GetLocalIPAsString() {
	if (this->ipType == IPType::IPV4) {
		return ConvertIP(this->localIPv4.S_un.S_addr);
	}
	return ConvertIPv6(&this->localIPv6);
}

std::wstring Connection::GetRemoteIPAsString() {
	if (this->ipType == IPType::IPV4) {
		return ConvertIP(this->remoteIPv4.S_un.S_addr);
	}
	return ConvertIPv6(&this->remoteIPv6);
}

std::wstring Connection::GetStateAsString() {
	if (this->State == MIB_TCP_STATE_CLOSED) {
		return L"MIB_TCP_STATE_CLOSED";
	}
	else if (this->State == MIB_TCP_STATE_LISTEN) {
		return L"MIB_TCP_STATE_LISTEN";
	}
	else if (this->State == MIB_TCP_STATE_ESTAB) {
		return L"MIB_TCP_STATE_ESTAB";
	}
	else if (this->State == MIB_TCP_STATE_SYN_RCVD) {
		return L"MIB_TCP_STATE_SYN_RCVD";
	}
	else if (this->State == MIB_TCP_STATE_SYN_SENT) {
		return L"MIB_TCP_STATE_SYN_SENT";
	}
	else if (this->State == MIB_TCP_STATE_FIN_WAIT1) {
		return L"MIB_TCP_STATE_FIN_WAIT1";
	}
	else if (this->State == MIB_TCP_STATE_FIN_WAIT2) {
		return L"MIB_TCP_STATE_FIN_WAIT2";
	}
	else if (this->State == MIB_TCP_STATE_CLOSE_WAIT) {
		return L"MIB_TCP_STATE_CLOSE_WAIT";
	}
	else if (this->State == MIB_TCP_STATE_CLOSING) {
		return L"MIB_TCP_STATE_CLOSING";
	}
	else if (this->State == MIB_TCP_STATE_LAST_ACK) {
		return L"MIB_TCP_STATE_LAST_ACK";
	}
	else if (this->State == MIB_TCP_STATE_TIME_WAIT) {
		return L"MIB_TCP_STATE_TIME_WAIT";
	}
	else if (this->State == MIB_TCP_STATE_DELETE_TCB) {
		return L"MIB_TCP_STATE_DELETE_TCB";
	}
	return L"";
}

bool operator==(const Connection& conn1, const Connection& conn2) {
	if (conn1.ipType != conn1.ipType) {
		return false;
	}

	if (conn1.localPort != conn2.localPort) {
		return false;
	}

	if (conn1.remotePort != conn2.remotePort) {
		return false;
	}

	if (conn1.State != conn2.State) {
		return false;
	}

	if (conn1.owningPid != conn2.owningPid) {
		return false;
	}

	if (conn1.protocol != conn2.protocol) {
		return false;
	}

	if (conn1.ipType == IPType::IPV4) {
		if (memcmp(&conn1.localIPv4,&conn2.localIPv4,sizeof(IN_ADDR)) != 0) {
			return false;
		}

		if (memcmp(&conn1.remoteIPv4, &conn2.remoteIPv4, sizeof(IN_ADDR)) != 0) {
			return false;
		}
	}
	else if (conn1.ipType == IPType::IPV6) {
		if (memcmp(&conn1.localIPv6, &conn2.localIPv6, sizeof(IN6_ADDR)) != 0) {
			return false;
		}

		if (memcmp(&conn1.remoteIPv6, &conn2.remoteIPv6, sizeof(IN6_ADDR)) != 0) {
			return false;
		}
	}

	return true;
}
