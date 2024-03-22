#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"

win::section_header_t* GetEnclosingSectionHeader(uint32_t rva, win::nt_headers_x64_t* pNTHeader) {
    auto section = pNTHeader->get_sections();
    for (unsigned i = 0; i < pNTHeader->file_header.num_sections; i++, section++) {
        if ((rva >= section->virtual_address) &&
            (rva < (section->virtual_address + section->virtual_size))) {
            return section;
        }
    }
    return 0;
}


uintptr_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva) {
    auto sectionHeader = ntHeaders->get_sections();
    for (int i = 0; i < ntHeaders->file_header.num_sections; i++, sectionHeader++) {
        if (rva >= sectionHeader->virtual_address && rva < (sectionHeader->virtual_address + sectionHeader->virtual_size)) {
            return rva - sectionHeader->virtual_address + sectionHeader->ptr_raw_data;
        }
    }
    return 0;
}


uintptr_t address_to_mapped_address(void* fileBase, uintptr_t rva) {

    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders = (win::nt_headers_x64_t*)((uint8_t*)fileBase + dosHeader->e_lfanew);

    auto ADDRESS = rva - ntHeaders->optional_header.image_base;
    return RvaToFileOffset(ntHeaders, ADDRESS);
}
