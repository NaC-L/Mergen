#pragma once

#include "CommandLineHelpers.hpp"
#include "Utils.h"
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

template <typename LiftEntryFn>
inline int runLifterApplication(const std::vector<std::string>& args,
                                LiftEntryFn&& liftEntry) {
  const char* programName = args.empty() ? "mergen-lifter" : args.front().c_str();
  if (args.size() < 3) {
    printLifterUsage(programName);
    return 1;
  }

  uint64_t startAddr = 0;
  if (!parseStartAddressArg(args[2], startAddr)) {
    std::cerr << "Invalid startAddr value: " << args[2] << std::endl;
    printLifterUsage(programName);
    return 1;
  }

  std::vector<uint8_t> fileData;
  if (!readBinaryFile(args[1], fileData)) {
    return 1;
  }

  const bool liftSucceeded =
      std::forward<LiftEntryFn>(liftEntry)(startAddr, std::move(fileData));
  if (!liftSucceeded) {
    return 1;
  }
  auto milliseconds = timer::stopTimer();
  std::cout << "\n"
            << std::dec << milliseconds << " milliseconds have passed"
            << std::endl;
  std::cout << "Lift and optimization pipeline completed" << std::endl;
  return 0;
}
