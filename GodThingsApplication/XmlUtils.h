#pragma once
#include "utils.h"
#include <map>
class XMLValueW {
	GTWString s;
public:
	GTWString AsWString();
	std::map<GTWString, XMLValueW> GetChilds();
	std::map<GTWString, GTWString> GetAttributes();
	XMLValueW(wchar_t* s);
};

class XMLParser {
public:
};