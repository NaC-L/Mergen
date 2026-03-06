#pragma once

#include "MemoryPolicySetup.hpp"
#include "RuntimeImageContext.hpp"
#include "Utils.h"
#include <memory>
#include <vector>

struct LifterStageContext {
  std::unique_ptr<lifterConcolic<>> lifter;
  RuntimeImageContext runtimeContext;
};

inline std::unique_ptr<lifterConcolic<>>
createConfiguredLifterForRuntime(uint8_t* fileBase, uint64_t runtimeAddress) {
  auto lifter = std::make_unique<lifterConcolic<>>();
  lifter->loadFile(fileBase);
  configureDefaultMemoryPolicy(lifter.get());

  lifter->blockInfo = BBInfo(runtimeAddress, lifter->bb);
  lifter->unvisitedBlocks.push_back(lifter->blockInfo);
  return lifter;
}

inline RuntimeImageContext
resolveRuntimeContextOrDie(uint8_t* fileBase, size_t fileSize,
                           uint64_t runtimeAddress) {
  x86FileReader file(fileBase);
  auto runtimeContext =
      createRuntimeImageContext(fileBase, fileSize, runtimeAddress, file);
  if (!runtimeContext.has_value()) {
    UNREACHABLE("Only PE files are supported");
  }

  return *runtimeContext;
}

inline LifterStageContext prepareLifterStageContext(
    uint64_t runtimeAddress, std::vector<uint8_t>& fileData) {
  auto fileBase = fileData.data();
  auto lifter = createConfiguredLifterForRuntime(fileBase, runtimeAddress);
  auto runtimeContext =
      resolveRuntimeContextOrDie(fileBase, fileData.size(), runtimeAddress);

  return LifterStageContext{.lifter = std::move(lifter),
                            .runtimeContext = runtimeContext};
}
