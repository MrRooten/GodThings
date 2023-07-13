#pragma once
#include "public.h"
#include <string>
#include <set>
#include "utils.h"
static std::set<std::wstring> privilegesSet;

static PTOKEN_PRIVILEGES pPrivileges;

BOOL HasPrivilege(std::wstring privilege);

BOOL GetSystem();

GTWString ConvertSidToUsername(const WCHAR* sid);

BOOL DebugPrivilege();