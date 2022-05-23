#include "Network.h"
#include "utils.h"
#include "ntapi.h"
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
DWORD TCPManager::SetTCPConnection() {
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
		conn->ipType = Connection::IPV4;
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
			conn->ipType = Connection::IPV6;
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

VOID TCPManager::UpdateTCPConnections() {

}

TCPManager::~TCPManager() {
	connections.clear();
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
	if (this->ipType == IPV4) {
		return ConvertIP(this->localIPv4.S_un.S_addr);
	}
	return ConvertIPv6(&this->localIPv6);
}

std::wstring Connection::GetRemoteIPAsString() {
	if (this->ipType == IPV4) {
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
