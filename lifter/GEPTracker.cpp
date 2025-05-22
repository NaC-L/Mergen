
#include "GEPTracker.h"
#include "nt/nt_headers.hpp"

namespace BinaryOperations {

  // ???, do this while creating the pass
  uint8_t* data_g;
  arch_mode is64Bit;
  bool concretize_unsafe_reads = 0;
  // this is the worst way of doing this

  void initBases(uint8_t* data, arch_mode is64) {
    data_g = data;
    is64Bit = is64;
  }

  int getBitness() { return is64Bit == X64 ? 64 : 32; }
  void getBases(uint8_t** data) { *data = data_g; }

  const char* getName(uint64_t offset) {
    auto dosHeader = (win::dos_header_t*)data_g;
    auto ntHeaders = (const void*)((uint8_t*)data_g + dosHeader->e_lfanew);
    auto rvaOffset = RvaToFileOffset(ntHeaders, offset);
    return (const char*)data_g + rvaOffset;
  }

  bool isImport(uint64_t addr) {
    auto dosHeader = reinterpret_cast<const win::dos_header_t*>(data_g);
    auto ntHeadersBase =
        reinterpret_cast<const uint8_t*>(data_g) + dosHeader->e_lfanew;

    uint64_t imageBase;
    if (is64Bit == X64) {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
      imageBase = ntHeaders->optional_header.image_base;
    } else {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
      imageBase = ntHeaders->optional_header.image_base;
    }

    APInt tmp;
    return readMemory(imageBase + addr, 1, tmp);
  }

  DenseSet<uint64_t> MemWrites;

  bool isWrittenTo(uint64_t addr) {
    return MemWrites.find(addr) != MemWrites.end();
  }

  void WriteTo(uint64_t addr) { MemWrites.insert(addr); }

  // sections
  bool readMemory(uint64_t addr, unsigned byteSize, APInt& value) {

    uint64_t mappedAddr = address_to_mapped_address(addr);
    uint64_t tempValue = 0;
    if (mappedAddr > 0) {
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(data_g + mappedAddr), byteSize);

      APInt readValue(byteSize * 8, tempValue);
      value = readValue;
      return 1;
    }

    return 0;
  }

  // TODO
  // 1- if writes into execute section, flag that address, if we execute that
  // address then do fancy stuff to figure out what we wrote so we know what
  // we will be executing
  void writeMemory();

  uint64_t RvaToFileOffset(const void* ntHeadersBase, uint32_t rva) {
    const auto* sectionHeader =
        is64Bit == X64
            ? reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase)
                  ->get_sections()
            : reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase)
                  ->get_sections();

    int numSections =
        is64Bit == X64
            ? reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase)
                  ->file_header.num_sections
            : reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase)
                  ->file_header.num_sections;

    for (int i = 0; i < numSections; i++, sectionHeader++) {
      if (rva >= sectionHeader->virtual_address &&
          rva <
              (sectionHeader->virtual_address + sectionHeader->virtual_size)) {

        return rva - sectionHeader->virtual_address +
               sectionHeader->ptr_raw_data;
      }
    }
    return 0;
  }

  uint64_t address_to_mapped_address(uint64_t rva) {
    auto dosHeader = reinterpret_cast<const win::dos_header_t*>(data_g);
    auto ntHeadersBase =
        reinterpret_cast<const uint8_t*>(data_g) + dosHeader->e_lfanew;

    uint64_t imageBase;
    if (is64Bit == X64) {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
      imageBase = ntHeaders->optional_header.image_base;
    } else {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
      imageBase = ntHeaders->optional_header.image_base;
    }

    uint64_t address = rva - imageBase;
    return RvaToFileOffset(ntHeadersBase, address);
  }

  uint64_t fileOffsetToRVA(uint64_t offset) {
    // this function is duplicate of RvaToFileOffset ??????????????
    if (!data_g) {
      return 0; // Ensure data is initialized
    }

    // Get DOS header
    auto dosHeader = reinterpret_cast<const win::dos_header_t*>(data_g);
    auto ntHeadersBase =
        reinterpret_cast<const uint8_t*>(data_g) + dosHeader->e_lfanew;

    // Determine NT headers based on architecture
    uint64_t imageBase;
    auto sectionHeader =
        is64Bit == X64
            ? reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase)
                  ->get_sections()
            : reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase)
                  ->get_sections();

    int numSections =
        is64Bit == X64
            ? reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase)
                  ->file_header.num_sections
            : reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase)
                  ->file_header.num_sections;

    imageBase =
        is64Bit == X64
            ? reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase)
                  ->optional_header.image_base
            : reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase)
                  ->optional_header.image_base;

    // Iterate over section headers to find matching section
    for (int i = 0; i < numSections; i++, sectionHeader++) {
      if (offset >= sectionHeader->ptr_raw_data &&
          offset <
              (sectionHeader->ptr_raw_data + sectionHeader->size_raw_data)) {

        if (!sectionHeader->characteristics
                 .mem_write) // if section is writeable, then it might be not
                             // safe to concretize this read, only do this if
                             // we are sure we want to do this
                             // also, this code is trash
          return imageBase + offset - sectionHeader->ptr_raw_data +
                 sectionHeader->virtual_address;
        else
          return 0;
      }
    }

    return 0; // Offset not found in any section
  }

}; // namespace BinaryOperations