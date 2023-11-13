#pragma once
#include "includes.h"


PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader);


uintptr_t RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva);


uintptr_t address_to_mapped_address(LPVOID fileBase, uintptr_t rva);