#pragma once
#include "public.h"

#include <iostream>
#include <string>

class NetworkUtils {
public:
	static IN_ADDR ConvertDWORDToIN_ADDR(DWORD address) {
		IN_ADDR a;
		a.S_un.S_addr = address;
		return a;
	}

	static in_addr6 ConvertBytesToIN_ADDR6(UCHAR* address) {
		in_addr6 addr;
		for (int i = 0; i < 16; i++) {
			addr.u.Byte[i] = address[i];
		}
		return addr;
	}
};
