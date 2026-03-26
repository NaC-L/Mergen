#pragma once

#include "MemoryPolicySetup.hpp"
#include "RuntimeImageContext.hpp"
#include "Utils.h"
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
createConfiguredLifterForRuntime(uint8_t* fileBase, uint64_t runtimeAddress) {
  auto lifter = std::make_unique<lifterConcolic<>>();
  lifter->loadFile(fileBase);
  // Memory policy configured later in prepareLifterStageContext
  // when RuntimeImageContext (with PE stack reserve) is available.

  // Auto-outline PE exports: exported functions are separate entry points
  // that should not be inlined when called from the lifted function.
  {
    auto* dosHdr = reinterpret_cast<win::dos_header_t*>(fileBase);
    auto* ntHdr  = reinterpret_cast<win::nt_headers_t<true>*>(
        fileBase + dosHdr->e_lfanew);
    auto& expDir = ntHdr->optional_header.data_directories.export_directory;
    if (expDir.size >= sizeof(win::export_directory_t)) {
      uint64_t imageBase = ntHdr->optional_header.image_base;
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

  auto lifter = createConfiguredLifterForRuntime(fileBase, runtimeAddress);
  auto ctx = *runtimeResult.context;
  configureDefaultMemoryPolicy(lifter.get(), ctx.stackReserve);
  return LifterStageContext{.lifter = std::move(lifter),
                            .runtimeContext = ctx};
}