#pragma once
#include "public.h"
#include <string>
#include <set>



static std::set<std::wstring> privilegesSet;
static PTOKEN_PRIVILEGES pPrivileges;
BOOL HasPrivilege(std::wstring privilege);

