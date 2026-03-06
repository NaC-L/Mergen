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
  if (args.size() < 3) {
    printLifterUsage(args[0].c_str());
    return 1;
  }

  uint64_t startAddr = 0;
  if (!parseStartAddressArg(args[2], startAddr)) {
    std::cerr << "Invalid startAddr value: " << args[2] << std::endl;
    printLifterUsage(args[0].c_str());
    return 1;
  }

  std::vector<uint8_t> fileData;
  if (!readBinaryFile(args[1], fileData)) {
    return 1;
  }

  std::forward<LiftEntryFn>(liftEntry)(startAddr, std::move(fileData));
  auto milliseconds = timer::stopTimer();
  std::cout << "\n"
            << std::dec << milliseconds << " milliseconds has past"
            << std::endl;
  std::cout << "Lifted and optimized " << debugging::increaseInstCounter() - 1
            << " total insts";
  return 0;
}
