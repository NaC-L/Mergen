#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"
#include "llvm/IR/Value.h"
win::section_header_t*
GetEnclosingSectionHeader(uint32_t rva, win::nt_headers_x64_t* pNTHeader) {
    auto section = pNTHeader->get_sections();
    for (unsigned i = 0; i < pNTHeader->file_header.num_sections;
         i++, section++) {
        if ((rva >= section->virtual_address) &&
            (rva < (section->virtual_address + section->virtual_size))) {

            return section;
        }
    }
    return 0;
}

uintptr_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva) {
    auto sectionHeader = ntHeaders->get_sections();
    for (int i = 0; i < ntHeaders->file_header.num_sections;
         i++, sectionHeader++) {
        if (rva >= sectionHeader->virtual_address &&
            rva < (sectionHeader->virtual_address +
                   sectionHeader->virtual_size)) {
            if (sectionHeader->characteristics.mem_execute ||
                (sectionHeader->characteristics.mem_read &&
                 !sectionHeader->characteristics.mem_write)) // remove?
                return rva - sectionHeader->virtual_address +
                       sectionHeader->ptr_raw_data;
            else
                return 0;
        }
    }
    return 0;
}

uintptr_t address_to_mapped_address(void* fileBase, uintptr_t rva) {
    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)fileBase + dosHeader->e_lfanew);
    auto ADDRESS = rva - ntHeaders->optional_header.image_base;
    return RvaToFileOffset(ntHeaders, ADDRESS);
}

namespace debugging {

    bool shouldDebug = false;
    void enableDebug() { shouldDebug = 1; }
    void printLLVMValue(llvm::Value* v, const char* name) {
        if (!shouldDebug)
            return;
        outs() << " " << name << " : ";
        v->print(outs());
        outs() << "\n";
        outs().flush();
    }
    void doIfDebug(const std::function<void(void)>& dothis) {
        if (!shouldDebug)
            return;
        (dothis)();
    }
    template <typename T> void printValue(const T& v, const char* name) {
        if (!shouldDebug)
            return;
        outs() << " " << name << " : ";
        outs() << v << "\n";
        outs().flush();
    }

    template void printValue<unsigned long>(const unsigned long& v,
                                            const char* name);
    template void printValue<long>(const long& v, const char* name);
    template void printValue<__int64>(const __int64& v, const char* name);
    template void printValue<KnownBits>(const KnownBits& v, const char* name);
    template void printValue<ROP_info>(const ROP_info& v, const char* name);
    template void printValue<unsigned long long>(const unsigned long long& v,
                                                 const char* name);

} // namespace debugging

namespace argparser {
    void loadArguments(int argc, char** argv) {}
} // namespace argparser

namespace timer {}