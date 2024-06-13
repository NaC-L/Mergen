#pragma once
#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"
#include "llvm/IR/Value.h"
#include <cstdint>
#include <linuxpe>

win::section_header_t*
GetEnclosingSectionHeader(uint32_t rva, win::nt_headers_x64_t* pNTHeader);

uintptr_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva);

uintptr_t address_to_mapped_address(void* fileBase, uintptr_t rva);

uintptr_t getSectionCharacteristics(void* fileBase, uintptr_t rva);

namespace debugging {
    int increaseInstCounter();
    void enableDebug();
    void printLLVMValue(llvm::Value* v, const char* name);
    void doIfDebug(const std::function<void(void)>& dothis);
    template <typename T> void printValue(const T& v, const char* name);
} // namespace debugging

namespace argparser {
    void parseArguments(std::vector<std::string>& args);
} // namespace argparser

namespace timer {
    void startTimer();
    double stopTimer();
    void suspendTimer();
    void resumeTimer();
} // namespace timer