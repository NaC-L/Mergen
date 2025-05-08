#ifndef FILEREADER_HPP
#define FILEREADER_HPP

#include "GEPTracker.h"
#include "nt/nt_headers.hpp"
#include "utils.h"
#include <coff/section_header.hpp>
#include <cstdint>

enum arch_mode : uint8_t { X86 = 0, X64 = 1 };
enum class characteristics : uint8_t {
  NONE = 1 << 0,
  R = 1 << 1,
  W = 1 << 2,
  X = 1 << 3,
  RW = R | W,
  RX = R | X,
  WX = W | X,
  RWX = R | W | X
};

inline characteristics operator|(characteristics lhs, characteristics rhs) {
  return static_cast<characteristics>(
      static_cast<std::underlying_type_t<characteristics>>(lhs) |
      static_cast<std::underlying_type_t<characteristics>>(rhs));
}

inline characteristics& operator|=(characteristics& lhs, characteristics rhs) {
  lhs = lhs | rhs;
  return lhs;
}

template <typename T>
concept FileRead = requires(T t) {
  { t.init_impl(std::declval<uint8_t*>()) } -> std::same_as<bool>;
  {
    t.address_to_mapped_address_impl(std::declval<uint64_t>())
  } -> std::same_as<uint64_t>;
};

template <typename Derived> class FileReader {
protected:
  uint8_t* fileBase;

public:
  FileReader() {
    static_assert(FileRead<Derived> && std::derived_from<Derived, FileReader>);
  };
  bool init(uint8_t* fileBase) {
    return static_cast<Derived*>(this)->init_impl(fileBase);
  }
  bool getMode() { return static_cast<Derived*>(this)->getMode_impl(); }
  uint64_t address_to_mapped_address(uint64_t rva) {
    return static_cast<Derived*>(this)->address_to_mapped_address_impl(rva);
  }
  bool readMemory(uint64_t rva, unsigned count, uint64_t& out) {
    return static_cast<Derived*>(this)->readMemory_impl(rva, count, out);
  }
  const char* getName(uint64_t offset) {
    return static_cast<Derived*>(this)->getName_impl(offset);
  }
  inline void filebase_exists() {
    assert(fileBase != nullptr && "fileBase is NULL");
  }
};

class x86FileReader : public FileReader<x86FileReader> {
public:
private:
  win::section_header_t* sectionHeader;
  int numSections;
  win::dos_header_t* dosHeader;
  uint8_t* ntHeadersBase;
  win::nt_headers_t<X86>* ntHeaders;
  uint64_t imageBase;
  std::vector<win::section_header_t> sections;

public:
  bool init_impl(uint8_t* fileBase) {

    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X86>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections.assign(rawSecs, rawSecs + numSections);

    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });

    return 1;
  }
  arch_mode getMode_impl() { return X86; }
  x86FileReader(uint8_t* fileBase) {

    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X86>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections.assign(rawSecs, rawSecs + numSections);

    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });
  };

  uint64_t RvaToFileOffset(uint32_t rva) {

    auto it =
        std::upper_bound(sections.begin(), sections.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections.begin()) {
      // rva is before the first section
      return 0;
    }
    --it; // now *it is the candidate section
    if (rva < it->virtual_address + it->virtual_size) {
      return (rva - it->virtual_address) + it->ptr_raw_data;
    }
    return 0;
  }

  uint64_t address_to_mapped_address_impl(uint64_t rva) {

    uint64_t address = rva - imageBase;
    return (uint64_t)fileBase + RvaToFileOffset(address);
  }

  bool readMemory_impl(uint64_t addr, unsigned byteSize, uint64_t& value) {

    uint64_t mappedAddr = address_to_mapped_address(addr);

    if (mappedAddr > 0) {
      uint64_t tempValue;
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(fileBase + mappedAddr),
                  byteSize);

      value = tempValue;
      return 1;
    }

    return 0;
  }

  const char* getName_impl(uint64_t offset) {
    auto rvaOffset = RvaToFileOffset(offset);
    return (const char*)fileBase + rvaOffset;
  }
};

class x86_64FileReader : public FileReader<x86_64FileReader> {
private:
  win::section_header_t* sectionHeader;
  int numSections;
  win::dos_header_t* dosHeader;
  uint8_t* ntHeadersBase;
  win::nt_headers_t<X64>* ntHeaders;
  uint64_t imageBase;
  std::vector<win::section_header_t> sections_v;
  std::vector<win::section_header_t> sections_r;

public:
  bool init_impl(uint8_t* fileBase) {

    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X64>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections_v.assign(rawSecs, rawSecs + numSections);

    std::sort(sections_v.begin(), sections_v.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });

    sections_r.assign(rawSecs, rawSecs + numSections);

    std::sort(sections_r.begin(), sections_r.end(),
              [](auto& a, auto& b) { return a.ptr_raw_data < b.ptr_raw_data; });

    return 1;
  }

  arch_mode getMode_impl() { return X64; }
  x86_64FileReader(){};
  x86_64FileReader(uint8_t* fileBase) { init(fileBase); };

  characteristics
  parseSectionCharacteristics(win::section_characteristics_t c) {
    characteristics res = characteristics::NONE;
    if (c.mem_read) {
      res |= characteristics::R;
    }
    if (c.mem_write) {
      res |= characteristics::W;
    }
    if (c.mem_execute) {
      res |= characteristics::X;
    }
    return res;
  }

  uint64_t RvaToFileOffset(uint32_t rva) {
    auto it =
        std::upper_bound(sections_v.begin(), sections_v.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });

    if (it == sections_v.begin())
      return 0;
    --it;

    if (rva < it->virtual_address + it->virtual_size) {

      return (rva - it->virtual_address) + it->ptr_raw_data;
    }

    return 0;
  }

  uint64_t fileOffsetToRVA(uint64_t offset) {
    auto it =
        std::upper_bound(sections_v.begin(), sections_v.end(), offset,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections_v.begin()) {
      // rva is before the first section
      return 0;
    }
    --it; // now *it is the candidate section
    if (offset < it->ptr_raw_data + it->size_raw_data) {
      return (offset - it->virtual_address) + it->ptr_raw_data;
    }
    return 0;
  }

  uint64_t address_to_mapped_address_impl(uint64_t rva) {
    printvalue2(rva);
    printvalue2(imageBase);
    uint64_t address = rva - imageBase;
    printvalue2(address);
    return (uint64_t)fileBase + RvaToFileOffset(address);
  }

  bool readMemory_impl(uint64_t addr, unsigned byteSize, uint64_t& value) {
    uint64_t mappedAddr = address_to_mapped_address(addr);

    if (mappedAddr > 0) {
      uint64_t tempValue;
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(fileBase + mappedAddr),
                  byteSize);

      value = tempValue;
      return 1;
    }

    return 0;
  }

  const char* getName_impl(uint64_t offset) {
    auto rvaOffset = RvaToFileOffset(offset);
    return (const char*)fileBase + rvaOffset;
  }
};

#endif // FILEREADER_HPP