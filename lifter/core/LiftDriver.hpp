#pragma once

#include "LifterClass_Concolic.hpp"
#include <iostream>

inline void runLiftWorklist(lifterConcolic<>* lifter) {
  BBInfo bbinfo;
  bool filter = false;

  while (lifter->getUnvisitedAddr(bbinfo, filter)) {
    if (!(bbinfo.block->empty()) && filter) {
      printvalue2("not empty");
      continue;
    }

    filter = true;
    lifter->load_backup(bbinfo.block);
    lifter->finished = 0;

    auto nextBlockName = bbinfo.block->getName();
    printvalue2(nextBlockName);

    lifter->builder->SetInsertPoint(bbinfo.block);
    lifter->liftBasicBlockFromAddress(bbinfo.block_address);
  }

  // Lifting summary: provides visibility into lift quality.
  std::cout << "Lift summary: "
            << lifter->liftStats.blocks_attempted << " blocks attempted, "
            << lifter->liftStats.blocks_completed << " completed, "
            << lifter->liftStats.blocks_unreachable << " unreachable, "
            << lifter->liftStats.instructions_lifted << " instructions, "
            << lifter->liftStats.instructions_unsupported << " unsupported"
            << std::endl;
}
