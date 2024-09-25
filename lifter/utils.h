#pragma once
#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"
#include "llvm/IR/Value.h"
#include <cstdint>
#include <linuxpe>

namespace FileHelper {

  win::section_header_t*
  GetEnclosingSectionHeader(uint32_t rva, win::nt_headers_x64_t* pNTHeader);

  uint64_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva);

  uint64_t address_to_mapped_address(uint64_t rva);

  uint64_t fileOffsetToRVA(uint64_t fileAddress);

  void setFileBase(void* base);

} // namespace FileHelper

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
  double getTimer();
  void suspendTimer();
  void resumeTimer();
} // namespace timer