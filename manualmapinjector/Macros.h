#pragma once
#include <Windows.h>

#define RELOC_FLAG32(x) ((x >> 0x0c) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(x) ((x >> 0x0c) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif