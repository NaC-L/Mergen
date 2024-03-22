#pragma once
#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"
#include <linuxpe>
#include <cstdint>

win::section_header_t* GetEnclosingSectionHeader(uint32_t rva, win::nt_headers_x64_t* pNTHeader);


uintptr_t RvaToFileOffset(win::nt_headers_x64_t*  ntHeaders, uint32_t rva);


uintptr_t address_to_mapped_address(void* fileBase, uintptr_t rva);
