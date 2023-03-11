#include "MagicUtils.h"
#include <stdio.h>
FileMagic::FileMagic(const CHAR* filename) {
	this->magic = magic_open(MAGIC_MIME_TYPE);
	auto load = magic_load(this->magic, filename);
}

const CHAR* FileMagic::FileFile(const CHAR* file) {
	return magic_file(this->magic, file);
}
