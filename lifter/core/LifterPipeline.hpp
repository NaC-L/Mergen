#pragma once

#include "LiftDriver.hpp"
#include "LifterPipelineStages.hpp"
#include "Utils.h"
#include <iostream>
#include <vector>

inline void runLifterPipeline(lifterConcolic<>* lifter,
                              const RuntimeImageContext& runtimeContext,
                              const uint8_t* fileBase,
                              std::vector<uint8_t>& fileData) {
  printRuntimeImageContext(runtimeContext, fileBase);
  prepareRuntimePagedMemory(lifter, runtimeContext);
  runSignatureStage(lifter, fileData);

  auto ms = captureElapsedMilliseconds();
  reportSignatureStageTiming(ms);

  runLiftWorklist(lifter);

  ms = captureElapsedMilliseconds();
  reportLiftCompletionTiming(ms);

  emitLiftOutputs(lifter, ms);
}
