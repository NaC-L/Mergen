#pragma once

#include "FileReader.hpp"
#include "nt/nt_headers.hpp"
#include <cstddef>
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
createRuntimeImageContext(const uint8_t* fileBase, size_t fileSize,
                         uint64_t runtimeAddress, x86FileReader& fileReader) {
  if (fileBase == nullptr || fileSize < sizeof(win::dos_header_t)) {
    return std::nullopt;
  }

  if (*reinterpret_cast<const uint16_t*>(fileBase) != 0x5a4d) {
    return std::nullopt;
  }

  auto dosHeader = reinterpret_cast<const win::dos_header_t*>(fileBase);
  const auto ntOffsetSigned = static_cast<int64_t>(dosHeader->e_lfanew);
  if (ntOffsetSigned < 0) {
    return std::nullopt;
  }

  const auto ntOffset = static_cast<size_t>(ntOffsetSigned);
  if (ntOffset > fileSize || fileSize - ntOffset < sizeof(win::nt_headers_t<false>)) {
    return std::nullopt;
  }

  auto ntHeadersBase = fileBase + ntOffset;
  auto ntHeaders32 = reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);

  constexpr auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
  constexpr auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
  const auto optionalHeaderMagic = ntHeaders32->optional_header.magic;
  if (optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
      optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return std::nullopt;
  }

  const bool is64Bit = optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  if (is64Bit && fileSize - ntOffset < sizeof(win::nt_headers_t<true>)) {
    return std::nullopt;
  }

  RuntimeImageContext context{};
  context.mode = is64Bit ? X64 : X86;

  if (is64Bit) {
    auto ntHeaders64 = reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
    context.imageBase = ntHeaders64->optional_header.image_base;
    context.imageSize = ntHeaders64->optional_header.size_image;
    context.stackReserve = ntHeaders64->optional_header.size_stack_reserve;
  } else {
    context.imageBase = ntHeaders32->optional_header.image_base;
    context.imageSize = ntHeaders32->optional_header.size_image;
    context.stackReserve = ntHeaders32->optional_header.size_stack_reserve;
  }

  if (runtimeAddress < context.imageBase) {
    return std::nullopt;
  }

  context.rva = runtimeAddress - context.imageBase;
  if (context.rva >= context.imageSize || context.rva > 0xFFFFFFFFull) {
    return std::nullopt;
  }

  context.fileOffset = fileReader.RvaToFileOffset(static_cast<uint32_t>(context.rva));
  if ((context.rva != 0 && context.fileOffset == 0) ||
      context.fileOffset >= fileSize) {
    return std::nullopt;
  }

  context.firstOpcodeByte = fileBase[context.fileOffset];
  return context;
}
