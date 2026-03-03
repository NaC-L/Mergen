#pragma once

#include "fileReader.hpp"
#include "nt/nt_headers.hpp"
#include <cstdint>
#include <optional>

struct RuntimeImageContext {
  arch_mode mode;
  uint64_t imageBase;
  uint64_t imageSize;
  uint64_t stackReserve;
  uint64_t rva;
  uint64_t fileOffset;
  uint8_t firstOpcodeByte;
};

inline std::optional<RuntimeImageContext>
createRuntimeImageContext(const uint8_t* fileBase, uint64_t runtimeAddress,
                         x86FileReader& fileReader) {
  if (fileBase == nullptr) {
    return std::nullopt;
  }

  if (*reinterpret_cast<const uint16_t*>(fileBase) != 0x5a4d) {
    return std::nullopt;
  }

  auto dosHeader = reinterpret_cast<const win::dos_header_t*>(fileBase);
  auto ntHeadersBase = fileBase + dosHeader->e_lfanew;
  auto ntHeaders64 = reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);

  constexpr auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
  const bool is64Bit = ntHeaders64->optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

  RuntimeImageContext context{};
  context.mode = is64Bit ? X64 : X86;

  if (is64Bit) {
    context.imageBase = ntHeaders64->optional_header.image_base;
    context.imageSize = ntHeaders64->optional_header.size_image;
    context.stackReserve = ntHeaders64->optional_header.size_stack_reserve;
  } else {
    auto ntHeaders32 =
        reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
    context.imageBase = ntHeaders32->optional_header.image_base;
    context.imageSize = ntHeaders32->optional_header.size_image;
    context.stackReserve = ntHeaders32->optional_header.size_stack_reserve;
  }

  if (runtimeAddress < context.imageBase) {
    return std::nullopt;
  }

  context.rva = runtimeAddress - context.imageBase;
  context.fileOffset = fileReader.RvaToFileOffset(static_cast<uint32_t>(context.rva));
  context.firstOpcodeByte = *(fileBase + context.fileOffset);

  return context;
}
