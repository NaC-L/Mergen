#pragma once

#include "RuntimeImageContext.hpp"
#include "LifterClass_Concolic.hpp"
#include "Utils.h"
#include <llvm/Support/raw_ostream.h>
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
  lifter->profiler.begin("write_unopt_ir");
  lifter->writeFunctionToFile("output_no_opts.ll");
  lifter->profiler.end();

  std::cout << "\nwriting complete, " << std::dec << elapsedMilliseconds
            << " milliseconds has past" << std::endl;

  lifter->profiler.begin("optimization");
  lifter->run_opts();
  lifter->profiler.end();

  lifter->profiler.begin("write_opt_ir");
  lifter->writeFunctionToFile("output.ll");
  lifter->profiler.end();

  // Write structured diagnostics + profile + stats to JSON.
  {
    auto& profile = lifter->profiler.getStages();
    auto json = lifter->diagnostics.toJson(&profile, &lifter->liftStats);
    std::string diagPath = "output_diagnostics.json";
    std::error_code EC;
    llvm::raw_fd_ostream diagFile(diagPath, EC);
    if (!EC) {
      diagFile << json;
      diagFile.close();
      if (diagFile.has_error()) {
        std::cerr << "[diagnostics] write error for " << diagPath << "\n";
        diagFile.clear_error();
      }
    } else {
      std::cerr << "[diagnostics] failed to open " << diagPath
                << ": " << EC.message() << "\n";
    }
    lifter->diagnostics.printSummary();
  }
}
