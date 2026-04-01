#pragma once

#include "LifterClass_Concolic.hpp"
#include <iostream>
#include <sstream>

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

    // Speculative call bail-out: the callee exceeded the inline budget.
    // This BB is the return continuation with pre-call state restored.
    // Emit CreateCall + ABI effects, then continue lifting normally.
    if (lifter->speculativeCall.bailedOut &&
        bbinfo.block_address == lifter->speculativeCall.returnAddr) {
      lifter->speculativeCall.bailedOut = false;

      lifter->builder->SetInsertPoint(bbinfo.block);

      // Emit an opaque call representing the outlined callee.
      auto& context = lifter->builder->getContext();
      auto fx = lifter->buildUnknownCallFx();
      fx.target = CallTargetClass::UnknownDirect;

      // The call target is unknown (we bailed out of inlining it).
      // Use a poison-ish constant so the IR shows what happened.
      auto* callTarget = llvm::ConstantInt::get(
          llvm::Type::getInt64Ty(context), 0xBA11ED);  // "bailed"
      auto* callPtr = lifter->builder->CreateIntToPtr(
          callTarget, llvm::PointerType::get(context, 0));

      auto* callResult = lifter->builder->CreateCall(
          lifter->parseArgsType(nullptr, context), callPtr,
          lifter->parseArgs(nullptr));

      lifter->applyPostCallEffects(callResult, fx);

      abi::printCallEffectsDiag(fx, bbinfo.block_address);
      std::cout << "[call-abi] outlined via speculative bail-out\n"
                << std::flush;

      // Now continue lifting from the return address normally.
    } else {
      lifter->builder->SetInsertPoint(bbinfo.block);
    }

    auto nextBlockName = bbinfo.block->getName();
    printvalue2(nextBlockName);

    lifter->liftBasicBlockFromAddress(bbinfo.block_address);
  }

  // Lifting summary remains in structured diagnostics; keep stdout quiet unless debugging.
  debugging::doIfDebug([&]() {
    std::cout << "Lift summary: "
              << lifter->liftStats.blocks_attempted << " blocks attempted, "
              << lifter->liftStats.blocks_completed << " completed, "
              << lifter->liftStats.blocks_unreachable << " unreachable, "
              << lifter->liftStats.instructions_lifted << " instructions, "
              << lifter->liftStats.instructions_unsupported << " unsupported"
              << std::endl;
  });
  {
    std::ostringstream ss;
    ss << lifter->liftStats.blocks_attempted << " blocks ("
       << lifter->liftStats.blocks_completed << " completed, "
       << lifter->liftStats.blocks_unreachable << " unreachable), "
       << lifter->liftStats.instructions_lifted << " instructions ("
       << lifter->liftStats.instructions_unsupported << " unsupported)";
    lifter->diagnostics.info(DiagCode::LiftComplete, 0, ss.str());
  }
}
