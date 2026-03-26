#pragma once

#include "RuntimeImageContext.hpp"
#include "LifterClass_Concolic.hpp"
#include "Utils.h"
#include <cstdint>
#include <iostream>
#include <vector>

inline void printRuntimeImageContext(const RuntimeImageContext& runtimeContext,
                                     const uint8_t* fileBase) {
  std::cout << std::hex << "0x" << static_cast<int>(runtimeContext.firstOpcodeByte)
            << std::endl;

  std::cout << "address: " << runtimeContext.imageBase
            << " imageSize: " << runtimeContext.imageSize
            << " filebase: " << reinterpret_cast<uint64_t>(fileBase)
            << " fOffset: " << runtimeContext.fileOffset
            << " RVA: " << runtimeContext.rva
            << " stackSize: " << runtimeContext.stackReserve << std::endl;
}

inline void prepareRuntimePagedMemory(lifterConcolic<>* lifter,
                                      const RuntimeImageContext& runtimeContext) {
  // Use the clamped stack reserve (set by configureDefaultMemoryPolicy) so that
  // pageMap and memoryPolicy agree on stack bounds. The raw PE header value
  // (runtimeContext.stackReserve) can be very large (e.g. 16MB) and would
  // create an unreasonably wide paged region.
  const uint64_t reserve = lifter->stackReserve;
  lifter->markMemPaged(STACKP_VALUE - reserve, STACKP_VALUE + reserve);
  printvalue2(reserve);
  lifter->markMemPaged(runtimeContext.imageBase,
                       runtimeContext.imageBase + runtimeContext.imageSize);
}

inline void runSignatureStage(lifterConcolic<>* lifter,
                              std::vector<uint8_t>& fileData) {
  lifter->signatures.search_signatures(fileData);
  lifter->signatures.createOffsetMap();
  for (const auto& [key, value] : lifter->signatures.siglookup) {
    value.display();
  }
}

inline double captureElapsedMilliseconds() { return timer::getTimer(); }

inline void reportSignatureStageTiming(double elapsedMilliseconds) {
  std::cout << "\n" << std::dec << elapsedMilliseconds
            << " milliseconds has past" << std::endl;
}

inline void reportLiftCompletionTiming(double elapsedMilliseconds) {
  std::cout << "\nlifting complete, " << std::dec << elapsedMilliseconds
            << " milliseconds has past" << std::endl;
}
inline void emitLiftOutputs(lifterConcolic<>* lifter, double elapsedMilliseconds) {
  lifter->writeFunctionToFile("output_no_opts.ll");

  std::cout << "\nwriting complete, " << std::dec << elapsedMilliseconds
            << " milliseconds has past" << std::endl;

  lifter->run_opts();
  lifter->writeFunctionToFile("output.ll");
}
