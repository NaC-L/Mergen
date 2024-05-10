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


// delet dis
void printsymbols(void* fileBase) {
    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders = (win::nt_headers_x64_t*)((uint8_t*)fileBase + dosHeader->e_lfanew);
    auto section = reinterpret_cast<win::image_thunk_data_t<>*>(ntHeaders->get_section(1));
    auto win_img = reinterpret_cast<win::image_t<>*>(fileBase);
    auto IATva = win_img->get_directory(win::directory_id::directory_entry_import)->rva;
    auto IAT = reinterpret_cast<win::import_directory_t*>(RvaToFileOffset(ntHeaders,IATva) + (uint8_t*)fileBase);
    outs() << IAT << "\n";
    outs() << IATva << "\n";
    outs() << IAT->rva_name << "\n";

    for (;
        IAT->rva_first_thunk; ++IAT) {
        IAT->rva_original_first_thunk;
        auto descriptoraddr = RvaToFileOffset(ntHeaders, IAT->rva_original_first_thunk) + (uint8_t*)fileBase;
        auto descriptoroffset = *(unsigned long long*)descriptoraddr;
        auto nameaddr = RvaToFileOffset(ntHeaders, descriptoroffset) + (uint8_t*)fileBase;
        outs() << ( (const char*)(nameaddr+2) ) << " " << descriptoroffset << "\n";
    }
    outs() << "\n";
}

uintptr_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva) {
    auto sectionHeader = ntHeaders->get_sections();
    for (int i = 0; i < ntHeaders->file_header.num_sections; i++, sectionHeader++) {
        if (rva >= sectionHeader->virtual_address && rva < (sectionHeader->virtual_address + sectionHeader->virtual_size)) {
            if (sectionHeader->characteristics.mem_read && !sectionHeader->characteristics.mem_write) // remove?
                return rva - sectionHeader->virtual_address + sectionHeader->ptr_raw_data;
            else
                return 0;
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
