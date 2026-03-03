#pragma once

#include "lifterClass_concolic.hpp"

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
}
