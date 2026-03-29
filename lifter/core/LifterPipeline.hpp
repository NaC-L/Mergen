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
  lifter->profiler.begin("pe_setup");
  printRuntimeImageContext(runtimeContext, fileBase);
  prepareRuntimePagedMemory(lifter, runtimeContext);
  lifter->profiler.end();

  lifter->profiler.begin("signature_search");
  runSignatureStage(lifter, fileData);
  lifter->profiler.end();

  auto ms = captureElapsedMilliseconds();
  reportSignatureStageTiming(ms);

  lifter->profiler.begin("lift");
  runLiftWorklist(lifter);
  lifter->profiler.end();

  ms = captureElapsedMilliseconds();
  reportLiftCompletionTiming(ms);

  emitLiftOutputs(lifter, ms);
}
