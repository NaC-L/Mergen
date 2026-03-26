#pragma once

#include "MemoryPolicySetup.hpp"
#include "RuntimeImageContext.hpp"
#include "Utils.h"
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