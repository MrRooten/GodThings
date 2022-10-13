#include "SystemUtils.h"

WORD SystemUtils::arch = PROCESSOR_ARCHITECTURE_UNKNOWN;
WORD SystemUtils::GetSystemArchitecture() {
    if (arch != PROCESSOR_ARCHITECTURE_UNKNOWN) {
        return arch;
    }

    SYSTEM_INFO info = { 0 };
    GetSystemInfo(&info);
    SystemUtils::arch = info.wProcessorArchitecture;
    return arch;
}
