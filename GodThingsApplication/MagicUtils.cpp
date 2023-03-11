#include "MagicUtils.h"
#include <stdio.h>
FileMagic::FileMagic(const CHAR* filename) {
	auto magic = magic_open(MAGIC_MIME_TYPE);
	auto load = magic_load(magic, "D:\\Tools\\vcpkg\\packages\\libmagic_x64-windows-static\\tools\\libmagic\\debug\\share\\misc\\magic.mgc");
	auto filetype = magic_file(magic, filename);
	printf("%s\n", filetype);
}
