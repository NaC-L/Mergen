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

enum class RuntimeImageContextError : uint8_t {
  None = 0,
  InvalidInputBuffer,
  InvalidDosMagic,
  InvalidNtHeaderOffset,
  NtHeadersOutOfRange,
  InvalidNtSignature,
  InvalidOptionalHeaderMagic,
  SectionTableOutOfRange,
  RuntimeAddressBelowImageBase,
  RuntimeAddressOutsideImage,
  RuntimeRvaTooLarge,
  RuntimeRvaUnmapped,
  FileOffsetOutOfRange,
};

inline const char*
runtimeImageContextErrorMessage(RuntimeImageContextError error) {
  switch (error) {
  case RuntimeImageContextError::None:
    return "no error";
  case RuntimeImageContextError::InvalidInputBuffer:
    return "input buffer is null or too small for a DOS header";
  case RuntimeImageContextError::InvalidDosMagic:
    return "input is not a PE file (missing MZ DOS magic)";
  case RuntimeImageContextError::InvalidNtHeaderOffset:
    return "PE DOS header contains an invalid NT header offset";
  case RuntimeImageContextError::NtHeadersOutOfRange:
    return "PE NT headers are truncated or out of file bounds";
  case RuntimeImageContextError::InvalidNtSignature:
    return "PE NT signature is invalid (expected PE\\0\\0)";
  case RuntimeImageContextError::InvalidOptionalHeaderMagic:
    return "PE optional header magic is neither PE32 nor PE32+";
  case RuntimeImageContextError::SectionTableOutOfRange:
    return "PE section table is truncated or out of file bounds";
  case RuntimeImageContextError::RuntimeAddressBelowImageBase:
    return "start address is below image base";
  case RuntimeImageContextError::RuntimeAddressOutsideImage:
    return "start address RVA is outside image size";
  case RuntimeImageContextError::RuntimeRvaTooLarge:
    return "start address RVA does not fit in 32 bits";
  case RuntimeImageContextError::RuntimeRvaUnmapped:
    return "start address RVA is not mapped to file-backed bytes";
  case RuntimeImageContextError::FileOffsetOutOfRange:
    return "resolved file offset is outside input file bounds";
  }
  return "unknown runtime context error";
}

struct RuntimeImageContextResult {
  std::optional<RuntimeImageContext> context{};
  RuntimeImageContextError error = RuntimeImageContextError::None;

  [[nodiscard]] bool ok() const { return context.has_value(); }
};

template <typename NtHeadersT>
inline bool validateSectionTableBounds(const uint8_t* fileBase, size_t fileSize,
                                       size_t ntOffset,
                                       RuntimeImageContextError& outError) {
  const auto* ntHeaders =
      reinterpret_cast<const NtHeadersT*>(fileBase + ntOffset);
  const uint64_t sectionHeaderOffset =
      static_cast<uint64_t>(ntOffset) + sizeof(uint32_t) +
      sizeof(win::file_header_t) + ntHeaders->file_header.size_optional_header;
  const uint64_t sectionTableBytes =
      static_cast<uint64_t>(ntHeaders->file_header.num_sections) *
      sizeof(win::section_header_t);

  if (sectionHeaderOffset > fileSize ||
      sectionTableBytes > (fileSize - sectionHeaderOffset)) {
    outError = RuntimeImageContextError::SectionTableOutOfRange;
    return false;
  }

  return true;
}

template <typename NtHeadersT>
inline std::optional<uint64_t> mapRvaToFileOffset(const NtHeadersT* ntHeaders,
                                                  uint32_t rva) {
  const auto* sections = ntHeaders->get_sections();
  const auto sectionCount = ntHeaders->file_header.num_sections;

  const auto headerSize =
      static_cast<uint64_t>(ntHeaders->optional_header.size_headers);
  if (static_cast<uint64_t>(rva) < headerSize) {
    return static_cast<uint64_t>(rva);
  }

  for (uint16_t index = 0; index < sectionCount; ++index) {
    const auto& section = sections[index];
    if (rva < section.virtual_address) {
      continue;
    }

    const auto offsetInSection = static_cast<uint64_t>(rva) -
                                 static_cast<uint64_t>(section.virtual_address);
    const auto mappedVirtualSize =
        section.virtual_size != 0 ? static_cast<uint64_t>(section.virtual_size)
                                  : static_cast<uint64_t>(section.size_raw_data);
    if (offsetInSection >= mappedVirtualSize) {
      continue;
    }

    if (offsetInSection >= section.size_raw_data) {
      return std::nullopt;
    }

    return static_cast<uint64_t>(section.ptr_raw_data) + offsetInSection;
  }

  return std::nullopt;
}

inline RuntimeImageContextResult
createRuntimeImageContext(const uint8_t* fileBase, size_t fileSize,
                         uint64_t runtimeAddress) {
  if (fileBase == nullptr || fileSize < sizeof(win::dos_header_t)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidInputBuffer};
  }

  if (*reinterpret_cast<const uint16_t*>(fileBase) != win::DOS_HDR_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidDosMagic};
  }

  const auto* dosHeader = reinterpret_cast<const win::dos_header_t*>(fileBase);
  const auto ntOffsetSigned = static_cast<int64_t>(dosHeader->e_lfanew);
  if (ntOffsetSigned < 0) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidNtHeaderOffset};
  }

  const auto ntOffset = static_cast<size_t>(ntOffsetSigned);
  if (ntOffset > fileSize ||
      fileSize - ntOffset < sizeof(win::nt_headers_t<false>)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::NtHeadersOutOfRange};
  }

  const auto* ntHeadersBase = fileBase + ntOffset;
  const auto* ntHeaders32 =
      reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
  if (ntHeaders32->signature != win::NT_HDR_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidNtSignature};
  }

  constexpr auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
  constexpr auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

  const auto optionalHeaderMagic = ntHeaders32->optional_header.magic;
  if (optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
      optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidOptionalHeaderMagic};
  }

  const bool is64Bit = optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  if (is64Bit && fileSize - ntOffset < sizeof(win::nt_headers_t<true>)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::NtHeadersOutOfRange};
  }

  RuntimeImageContextError sectionError = RuntimeImageContextError::None;
  if (is64Bit) {
    if (!validateSectionTableBounds<win::nt_headers_t<true>>(fileBase, fileSize,
                                                             ntOffset, sectionError)) {
      return {.context = std::nullopt, .error = sectionError};
    }
  } else {
    if (!validateSectionTableBounds<win::nt_headers_t<false>>(fileBase, fileSize,
                                                              ntOffset, sectionError)) {
      return {.context = std::nullopt, .error = sectionError};
    }
  }

  RuntimeImageContext context{};
  context.mode = is64Bit ? X64 : X86;

  std::optional<uint64_t> fileOffset;
  if (is64Bit) {
    const auto* ntHeaders64 =
        reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
    context.imageBase = ntHeaders64->optional_header.image_base;
    context.imageSize = ntHeaders64->optional_header.size_image;
    context.stackReserve = ntHeaders64->optional_header.size_stack_reserve;

    if (runtimeAddress < context.imageBase) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressBelowImageBase};
    }

    context.rva = runtimeAddress - context.imageBase;
    if (context.rva >= context.imageSize) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressOutsideImage};
    }
    if (context.rva > 0xFFFFFFFFull) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeRvaTooLarge};
    }

    fileOffset = mapRvaToFileOffset(ntHeaders64, static_cast<uint32_t>(context.rva));
  } else {
    context.imageBase = ntHeaders32->optional_header.image_base;
    context.imageSize = ntHeaders32->optional_header.size_image;
    context.stackReserve = ntHeaders32->optional_header.size_stack_reserve;

    if (runtimeAddress < context.imageBase) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressBelowImageBase};
    }

    context.rva = runtimeAddress - context.imageBase;
    if (context.rva >= context.imageSize) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressOutsideImage};
    }
    if (context.rva > 0xFFFFFFFFull) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeRvaTooLarge};
    }

    fileOffset = mapRvaToFileOffset(ntHeaders32, static_cast<uint32_t>(context.rva));
  }

  if (!fileOffset.has_value()) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::RuntimeRvaUnmapped};
  }

  context.fileOffset = *fileOffset;
  if (context.fileOffset >= fileSize) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::FileOffsetOutOfRange};
  }

  context.firstOpcodeByte = fileBase[context.fileOffset];
  return {.context = context, .error = RuntimeImageContextError::None};
}