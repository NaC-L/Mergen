#pragma once

#include "MemoryPolicySetup.hpp"
#include "RuntimeImageContext.hpp"
#include "Utils.h"
#include <nt/directories/dir_import.hpp>
#include <nt/directories/dir_export.hpp>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

struct LifterStageContext {
  std::unique_ptr<lifterConcolic<>> lifter;
  RuntimeImageContext runtimeContext;
};

inline std::unique_ptr<lifterConcolic<>>
createConfiguredLifterForRuntime(uint8_t* fileBase, size_t fileSize,
                                uint64_t runtimeAddress) {
  auto lifter = std::make_unique<lifterConcolic<>>();
  lifter->loadFile(fileBase);
  // Memory policy configured later in prepareLifterStageContext
  // when RuntimeImageContext (with PE stack reserve) is available.

  // Parse PE headers once for all directory walks below.
  auto* dosHdr = reinterpret_cast<win::dos_header_t*>(fileBase);
  auto* ntHdr  = reinterpret_cast<win::nt_headers_t<true>*>(
      fileBase + dosHdr->e_lfanew);
  uint64_t imageBase = ntHdr->optional_header.image_base;

  // Auto-outline PE exports: exported functions are separate entry points
  // that should not be inlined when called from the lifted function.
  {
    auto& expDir = ntHdr->optional_header.data_directories.export_directory;
    if (expDir.size >= sizeof(win::export_directory_t)) {
      auto fileOff = lifter->file.RvaToFileOffset(expDir.rva);
      if (fileOff != 0) {
        auto* exp = reinterpret_cast<const win::export_directory_t*>(
            fileBase + fileOff);
        auto funcTableOff = lifter->file.RvaToFileOffset(exp->rva_functions);
        if (funcTableOff != 0 && exp->num_functions > 0) {
          auto* funcRVAs = reinterpret_cast<const uint32_t*>(
              fileBase + funcTableOff);
          for (uint32_t i = 0; i < exp->num_functions; ++i) {
            uint32_t rva = funcRVAs[i];
            if (rva == 0) continue;
            // Skip forwarded exports: RVA points within the export directory
            // itself (to an ASCII forwarder string, not code).
            if (rva >= expDir.rva && rva < expDir.rva + expDir.size) continue;
            lifter->inlinePolicy.addAddress(imageBase + rva);
          }
        }
      }
    }
  }

  // Build import name map: IAT slot VA -> function name.
  // This enables named CreateCall declarations for outlined import thunks.
  {
    auto& impDir = ntHdr->optional_header.data_directories.import_directory;
    if (impDir.size >= sizeof(win::import_directory_t)) {
      auto impOff = lifter->file.RvaToFileOffset(impDir.rva);
      if (impOff != 0) {
        auto* imports = reinterpret_cast<const win::import_directory_t*>(
            fileBase + impOff);
        // Walk import descriptors until the null terminator.
        for (; imports->rva_name != 0; ++imports) {
          auto iltOff = lifter->file.RvaToFileOffset(
              imports->rva_original_first_thunk);
          auto iatOff = lifter->file.RvaToFileOffset(
              imports->rva_first_thunk);
          if (iatOff == 0) continue;
          // PE spec: if OriginalFirstThunk is zero, use FirstThunk for
          // name lookup (common with bound imports and some linkers).
          if (iltOff == 0) iltOff = iatOff;

          auto* ilt = reinterpret_cast<const uint64_t*>(fileBase + iltOff);
          uint32_t iatRva = imports->rva_first_thunk;
          // Cap iteration to prevent walking off mapped memory when the
          // ILT lacks a null terminator (truncated/malformed PE).
          size_t maxIltEntries = (fileSize > iltOff) ? (fileSize - iltOff) / 8 : 0;

          for (size_t i = 0; i < maxIltEntries && ilt[i] != 0; ++i) {
            uint64_t iatSlotVA = imageBase + iatRva + i * 8;
            // Bit 63 set = import by ordinal, no name available.
            if (ilt[i] & (1ULL << 63)) continue;
            // Bits 30:0 = RVA to hint/name entry {uint16_t hint; char name[]}.
            uint32_t hintNameRva = static_cast<uint32_t>(ilt[i] & 0x7FFFFFFF);
            auto hnOff = lifter->file.RvaToFileOffset(hintNameRva);
            if (hnOff == 0) continue;
            // Bounds-check: hint (2 bytes) + at least 1 byte of name must
            // fit within the file buffer.
            if (hnOff + 3 > fileSize) continue;
            const char* funcName =
                reinterpret_cast<const char*>(fileBase + hnOff + 2);
            // Ensure the name is null-terminated within the file.
            size_t maxLen = fileSize - (hnOff + 2);
            if (strnlen(funcName, maxLen) == maxLen) continue;
            lifter->importMap[iatSlotVA] = funcName;
          }
        }
      }
    }
  }

  // Auto-outline .pdata function starts: real functions with unwind info
  // should be outlined when called, not inlined.  Validates each entry
  // (rva_begin < imageSize and rva_begin < rva_end) to discard garbage
  // entries produced by obfuscators like VMP.
  {
    auto& excDir = ntHdr->optional_header.data_directories.exception_directory;
    uint32_t imageSize = ntHdr->optional_header.size_image;
    if (excDir.size >= 12) {
      auto excOff = lifter->file.RvaToFileOffset(excDir.rva);
      if (excOff != 0) {
        // Each RUNTIME_FUNCTION is {uint32_t BeginAddress, EndAddress, UnwindInfo}.
        // Clamp to actual file bounds to prevent OOB reads on corrupted headers.
        size_t safeSize = (excOff < fileSize) ? std::min<size_t>(excDir.size, fileSize - excOff) : 0;
        size_t numEntries = safeSize / 12;
        const uint8_t* entries = fileBase + excOff;
        size_t added = 0;
        for (size_t i = 0; i < numEntries; ++i) {
          uint32_t rvaBegin, rvaEnd;
          std::memcpy(&rvaBegin, entries + i * 12, 4);
          std::memcpy(&rvaEnd,   entries + i * 12 + 4, 4);
          // Validate: both RVAs inside image, begin < end.
          if (rvaBegin >= imageSize || rvaEnd > imageSize || rvaBegin >= rvaEnd)
            continue;
          // Skip the start address itself — it's the root, not a call target.
          uint64_t funcVA = imageBase + rvaBegin;
          if (funcVA == runtimeAddress) continue;
          lifter->inlinePolicy.addAddress(funcVA);
          ++added;
        }
        if (added > 0) {
          debugging::doIfDebug([&]() {
            std::cout << "[outline] .pdata: " << added
                      << " function starts added to outline set\n" << std::flush;
          });
          lifter->diagnostics.info(DiagCode::PdataOutlineCount, 0,
                                  std::to_string(added) + " .pdata function starts outlined");
        }
      }
    }
  }

  lifter->blockInfo = BBInfo(runtimeAddress, lifter->bb);
  lifter->unvisitedBlocks.push_back(lifter->blockInfo);
  return lifter;
}

inline std::string formatAddressHex(uint64_t address) {
  std::ostringstream oss;
  oss << "0x" << std::hex << address;
  return oss.str();
}

inline std::string formatRuntimeContextFailure(RuntimeImageContextError error,
                                               uint64_t runtimeAddress) {
  std::ostringstream oss;
  oss << "Failed to resolve runtime context: "
      << runtimeImageContextErrorMessage(error)
      << " (start address: " << formatAddressHex(runtimeAddress) << ")";
  return oss.str();
}

inline std::optional<LifterStageContext>
prepareLifterStageContext(uint64_t runtimeAddress, std::vector<uint8_t>& fileData,
                         std::string& outError) {
  if (fileData.empty()) {
    outError = "Input file is empty";
    return std::nullopt;
  }

  auto* fileBase = fileData.data();
  auto runtimeResult =
      createRuntimeImageContext(fileBase, fileData.size(), runtimeAddress);
  if (!runtimeResult.ok()) {
    outError = formatRuntimeContextFailure(runtimeResult.error, runtimeAddress);
    return std::nullopt;
  }

  auto lifter = createConfiguredLifterForRuntime(fileBase, fileData.size(),
                                                 runtimeAddress);
  auto ctx = *runtimeResult.context;
  configureDefaultMemoryPolicy(lifter.get(), ctx.stackReserve);
  return LifterStageContext{.lifter = std::move(lifter),
                            .runtimeContext = ctx};
}