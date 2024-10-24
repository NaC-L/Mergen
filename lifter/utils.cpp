#include "coff/section_header.hpp"
#include "includes.h"
#include "nt/nt_headers.hpp"
#include "llvm/IR/Value.h"
#include <llvm/Analysis/ValueLattice.h>
#include <ratio>
namespace FileHelper {

  static void* fileBase = nullptr;

  void setFileBase(void* base) { fileBase = base; }

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

  uint64_t RvaToFileOffset(win::nt_headers_x64_t* ntHeaders, uint32_t rva) {
    auto sectionHeader = ntHeaders->get_sections();
    for (int i = 0; i < ntHeaders->file_header.num_sections;
         i++, sectionHeader++) {
      if (rva >= sectionHeader->virtual_address &&
          rva <
              (sectionHeader->virtual_address + sectionHeader->virtual_size)) {
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

  uint64_t address_to_mapped_address(uint64_t rva) {
    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)fileBase + dosHeader->e_lfanew);
    auto ADDRESS = rva - ntHeaders->optional_header.image_base;
    return RvaToFileOffset(ntHeaders, ADDRESS);
  }

  uint64_t fileOffsetToRVA(uint64_t offset) {
    if (!fileBase)
      return 0;
    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)fileBase + dosHeader->e_lfanew);

    auto sectionHeader = ntHeaders->get_sections();
    for (int i = 0; i < ntHeaders->file_header.num_sections;
         i++, sectionHeader++) {
      if (offset >= sectionHeader->ptr_raw_data &&
          offset <
              (sectionHeader->ptr_raw_data + sectionHeader->size_raw_data)) {
        return ntHeaders->optional_header.image_base + offset -
               sectionHeader->ptr_raw_data + sectionHeader->virtual_address;
      }
    }
    return 0;
  }

} // namespace FileHelper
namespace debugging {
  int ic = 1;
  int increaseInstCounter() { return ++ic; }
  bool shouldDebug = false;
  void enableDebug() {
    shouldDebug = 1;
    cout << "Debugging enabled\n";
  }
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
    outs() << " " << name << " : " << v << "\n";
    outs().flush();
  }

  template void printValue<uint64_t>(const uint64_t& v, const char* name);
  template void printValue<uint32_t>(const uint32_t& v, const char* name);
  template void printValue<uint16_t>(const uint16_t& v, const char* name);
  template void printValue<uint8_t>(const uint8_t& v, const char* name);
  template void printValue<int64_t>(const int64_t& v, const char* name);
  template void printValue<int32_t>(const int32_t& v, const char* name);
  template void printValue<int16_t>(const int16_t& v, const char* name);
  template void printValue<int8_t>(const int8_t& v, const char* name);
  template void printValue<bool>(const bool& v, const char* name);
  template void printValue<std::string>(const std::string& v, const char* name);
  template void printValue<char*>(char* const& v, const char* name);
  template void printValue<z3::expr>(const z3::expr& v, const char* name);
  template void printValue<char[256]>(char const (&)[256], const char* name);
  template void
  printValue<llvm::FormattedNumber>(llvm::FormattedNumber const(&),
                                    const char* name);
  template void
  printValue<llvm::ValueLatticeElement>(const llvm::ValueLatticeElement& v,
                                        const char* name);
  template void printValue<llvm::KnownBits>(const llvm::KnownBits& v,
                                            const char* name);
  template void printValue<llvm::APInt>(const llvm::APInt& v, const char* name);
  template void printValue<llvm::ConstantRange>(const llvm::ConstantRange& v,
                                                const char* name);
} // namespace debugging

namespace argparser {
  void printHelp() {
    std::cerr << "Options:\n"
              << "  -d, --enable-debug   Enable debugging mode\n"
              << "  -h                   Display this help message\n";
  }

  std::map<std::string, std::function<void()>> options = {
      {"-d", debugging::enableDebug},
      {"--enable-debug", debugging::enableDebug},
      {"-h", printHelp}};

  void parseArguments(std::vector<std::string>& args) {
    std::vector<std::string> newArgs;

    for (const auto& arg : args) {
      // cout << arg << "\n";
      if (options.find(arg) != options.end())
        options[arg]();
      else if (*(arg.c_str()) == '-')
        printHelp();
      else
        newArgs.push_back(arg);
    }

    args.swap(newArgs);
  }

} // namespace argparser

namespace timer {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double, std::milli>;

  time_point startTime;
  duration elapsedTime{0};
  bool running = false;

  void startTimer() {
    startTime = clock::now();
    running = true;
  }

  double getTimer() {
    elapsedTime += clock::now() - startTime;
    return elapsedTime.count();
  }

  double stopTimer() {
    if (running) {
      elapsedTime += clock::now() - startTime;
      running = false;
    }
    return elapsedTime.count();
  }

  void suspendTimer() {
    if (running) {
      elapsedTime += clock::now() - startTime;
      running = false;
    }
  }

  void resumeTimer() {
    if (!running) {
      startTime = clock::now();
      running = true;
    }
  }
} // namespace timer