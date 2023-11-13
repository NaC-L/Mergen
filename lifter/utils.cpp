#pragma once
#include "includes.h"

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    for (unsigned i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++) {
        if ((rva >= section->VirtualAddress) &&
            (rva < (section->VirtualAddress + section->Misc.VirtualSize))) {
            return section;
        }
    }
    return 0;
}


uintptr_t RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
        if (rva >= sectionHeader->VirtualAddress && rva < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
            return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
        }
    }
    return 0;
}


uintptr_t address_to_mapped_address(LPVOID fileBase, uintptr_t rva) {

    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(fileBase) + dosHeader->e_lfanew);

    auto ADDRESS = rva - ntHeaders->OptionalHeader.ImageBase;
    return RvaToFileOffset(ntHeaders, ADDRESS);
}