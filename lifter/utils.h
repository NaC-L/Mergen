#pragma once
#include "coff/section_header.hpp"
#include "nt/nt_headers.hpp"
#include "llvm/IR/Value.h"
#include <cstdint>
#include <linuxpe>

// #define _NODEV why?

#ifndef UNREACHABLE
#define UNREACHABLE(msg)                                                       \
  do {                                                                         \
                                                                               \
    llvm::outs().flush();                                                      \
    std::cout.flush();                                                         \
    llvm_unreachable_internal(msg, __FILE__, __LINE__);                        \
  } while (0)
#endif

#ifndef _NODEV
#define printvalue(x)                                                          \
  do {                                                                         \
    debugging::printLLVMValue(x, #x);                                          \
  } while (0);
// outs() << " " #x " : "; x->print(outs());
// outs() << "\n";  outs().flush();
#define printvalue2(x)                                                         \
  do {                                                                         \
    debugging::printValue(x, #x);                                              \
  } while (0);
#else
#define printvalue(x) ((void)0);
#define printvalue2(x) ((void)0);
#endif // _NODEV

#define printvalueforce(x)                                                     \
  do {                                                                         \
    outs() << " " #x " : ";                                                    \
    x->print(outs());                                                          \
    outs() << "\n";                                                            \
    outs().flush();                                                            \
  } while (0);

#define printvalueforce2(x)                                                    \
  do {                                                                         \
    outs() << " " #x " : " << x << "\n";                                       \
    outs().flush();                                                            \
  } while (0);

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
} // namespace timer