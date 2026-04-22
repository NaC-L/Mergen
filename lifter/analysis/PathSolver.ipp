#pragma once

#include "CommonDisassembler.hpp"
#include "PathSolver.h"
#include "LifterClass.hpp"
#include "Utils.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/Analysis/MemorySSAUpdater.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/Casting.h>
#include <limits>

MERGEN_LIFTER_DEFINITION_TEMPLATES(PATH_info)::solvePath(
    llvm::Function* function, uint64_t& dest, Value* simplifyValue) {
  auto pathSolveSample = profiler.sample("lift_path_solve");

  // Clear memoization cache for value enumeration.
  // Each solvePath invocation may have different assumptions
  // (from different branch paths), so cached results don't carry over.
  pv_cache.clear();
  const uint64_t pathSolveSite = current_address - instruction.length;
  if (auto* loadInst = dyn_cast<LoadInst>(simplifyValue)) {
    if (loadInst->getType()->isIntegerTy()) {
      auto* gep = dyn_cast<GetElementPtrInst>(loadInst->getPointerOperand());
      if (gep && gep->getPointerOperand() == memoryAlloc) {
        unsigned loadBits = loadInst->getType()->getIntegerBitWidth();
        if (loadBits % 8 == 0) {
          LazyValue nestedLoad([loadInst]() -> Value* { return loadInst; });
          if (auto* resolved = solveLoad(
                  nestedLoad, gep, static_cast<uint8_t>(loadBits / 8))) {
            if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
              std::string resolvedText;
              llvm::raw_string_ostream os(resolvedText);
              resolved->print(os);
              std::cout << "[diag] solvePath eager load current=0x1400237f9 resolved="
                        << os.str() << "\n";
            }
            if (currentPathSolveContext == PathSolveContext::IndirectJump) {
              if (auto* resolvedCI = dyn_cast<ConstantInt>(resolved)) {
                uint64_t normalizedResolved =
                    normalizeRuntimeTargetAddress(resolvedCI->getZExtValue());
                if (!isMemPaged(normalizedResolved)) {
                  if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
                    std::cout << "[diag] solvePath eager load skipping unmapped constant=0x"
                              << std::hex << resolvedCI->getZExtValue()
                              << " normalized=0x" << normalizedResolved << std::dec
                              << "\n";
                  }
                } else {
                  simplifyValue = resolved;
                }
              } else {
                simplifyValue = resolved;
              }
            } else {
              simplifyValue = resolved;
            }
          } else if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
            std::string offsetText;
            llvm::raw_string_ostream os(offsetText);
            gep->getOperand(1)->print(os);
            std::cout << "[diag] solvePath eager load current=0x1400237f9 returned-null offset="
                      << os.str() << "\n";
          }
        }
      }
    }
  }
  auto normalizeTargetAddress = [&](uint64_t target) -> uint64_t {
    return normalizeRuntimeTargetAddress(target);
  };

  struct ResolvedTargetBlock {
    BasicBlock* block;
    bool reusedBackedge;
    bool generalizedBackup;
  };

  auto resolveTargetBlock = [&](uint64_t target, const std::string& name)
      -> ResolvedTargetBlock {
    if (auto* reused = getLiftedBackedgeBB(target)) {
      record_generalized_loop_backedge(reused);
      return {reused, true, false};
    }

    const bool backwardVisitedTarget =
        visitedAddresses.contains(target) &&
        target <= blockInfo.block_address;
    auto it = addrToBB.find(target);
    const bool hasPendingGeneralization =
        pendingLoopGeneralizationAddresses.contains(target);
    // `resolveTargetBlock` is only reached with a concrete destination, so an
    // indirect jump whose target has just resolved participates in the same
    // structured-loop generalization path that direct and conditional jumps
    // already take.
    const bool canUseStructuredLoopGeneralization =
        currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget();
    const bool canReusePendingGeneralization =
        hasPendingGeneralization && canUseStructuredLoopGeneralization;
    const bool wantsGeneralization =
        canReusePendingGeneralization ||
        (backwardVisitedTarget &&
         canGeneralizeStructuredLoopHeader(target,
                                           /*targetResolvedConcretely=*/true));
    if (wantsGeneralization) {
      // A resolved backward target participates in the same stack-concolic
      // bypass regime regardless of whether the source jump is direct or
      // indirect — both represent a confirmed loop back-edge.
      if (currentPathSolveContext == PathSolveContext::DirectJump ||
          currentPathSolveContext == PathSolveContext::IndirectJump) {
        stackBypassGeneralizedLoopAddresses.insert(target);
      }
      const bool generalizedBackup =
          canUseStructuredLoopGeneralization &&
          stackBypassGeneralizedLoopAddresses.contains(target);
      if (canReusePendingGeneralization && it != addrToBB.end() && it->second &&
          it->second->empty()) {
        return {it->second, false, generalizedBackup};
      }
      if (!hasPendingGeneralization) {
        pendingLoopGeneralizationAddresses.insert(target);
      }
      if (it != addrToBB.end() && it->second && !it->second->empty()) {
        return {replaceWithGeneralizedLoopBlock(target, name), false,
                generalizedBackup};
      }
      return {getOrCreateBB(target, name), false, generalizedBackup};
    }

    return {getOrCreateBB(target, name), false, false};
  };

  auto backupQueuedTarget = [&](BasicBlock* targetBlock, bool generalizedBackup) {
    if (targetBlock == liftAbortBlock) {
      return;
    }
    branch_backup(targetBlock, generalizedBackup);
  };

  // do static polymorphism here

  auto shouldTraceHotPathSolve = [&]() {
    return liftProgressDiagEnabled && pathSolveSite >= 0x140023582ULL &&
           pathSolveSite <= 0x140023FFFULL;
  };
  auto formatPathValue = [](llvm::Value* value) {
    if (!value) {
      return std::string("<null>");
    }
    std::string text;
    llvm::raw_string_ostream os(text);
    value->print(os);
    return os.str();
  };

  PATH_info result = PATH_unsolved;
  if (shouldTraceHotPathSolve()) {
    std::cout << "[diag] solvePath site=0x" << std::hex << pathSolveSite
              << std::dec << " value=" << formatPathValue(simplifyValue) << "\n";
  }
  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplifyValue)) {
    dest = normalizeTargetAddress(constInt->getZExtValue());
    result = PATH_solved;
    run = 0;

    auto resolved = resolveTargetBlock(dest, "bb_solved_const");

    builder->CreateBr(resolved.block);
    if (!resolved.reusedBackedge) {
      blockInfo = BBInfo(dest, resolved.block);
      printvalue2("pushing block");
      backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
      unvisitedBlocks.push_back(blockInfo);
    }

    return result;
  }

  if (PATH_info solved = getConstraintVal(function, simplifyValue, dest)) {
      dest = normalizeTargetAddress(dest);
    if (solved == PATH_solved) {
      run = 0;
      std::cout << "Solved the constraint and moving to next path\n"
                << std::flush;

      auto resolved = resolveTargetBlock(dest, "bb_solved");

      builder->CreateBr(resolved.block);
      if (!resolved.reusedBackedge) {
        blockInfo = BBInfo(dest, resolved.block);
        printvalue2("pushing block");
        backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
        unvisitedBlocks.push_back(blockInfo);
      }

      return solved;
    }
  }

  // unsolved
  printvalue(simplifyValue);
  run = 0;
  auto pvset = computePossibleValues(simplifyValue);
  std::vector<APInt> pv(pvset.begin(), pvset.end());
  if (shouldTraceHotPathSolve()) {
    std::cout << "[diag] solvePath site=0x" << std::hex << pathSolveSite
              << std::dec << " pv_count=" << pvset.size();
    size_t shown = 0;
    for (const auto& candidate : pvset) {
      if (shown++ >= 4) {
        std::cout << " ...";
        break;
      }
      std::cout << " candidate=0x" << std::hex << candidate.getZExtValue()
                << std::dec;
    }
    std::cout << "\n";
  }
  if (pv.size() == 1) {
    printvalue2(pv[0]);
    dest = normalizeTargetAddress(pv[0].getZExtValue());
    result = PATH_solved;

    auto resolved = resolveTargetBlock(dest, "bb_single");
    builder->CreateBr(resolved.block);
    if (!resolved.reusedBackedge) {
      blockInfo = BBInfo(dest, resolved.block);
      printvalue2("pushing block");
      backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
      unvisitedBlocks.push_back(blockInfo);
    }
    return result;
  }
  if (pv.size() == 2) {
    uint64_t rawFirstTarget = pv[0].getZExtValue();
    uint64_t rawSecondTarget = pv[1].getZExtValue();
    uint64_t filteredFirstTarget = normalizeTargetAddress(rawFirstTarget);
    uint64_t filteredSecondTarget = normalizeTargetAddress(rawSecondTarget);
    auto isViableIndirectTarget = [&](uint64_t rawTarget, uint64_t normalizedTarget) {
      return rawTarget != 0 && normalizedTarget != 0 &&
             isMemPaged(normalizedTarget);
    };
    if (currentPathSolveContext == PathSolveContext::IndirectJump) {
      const bool firstViable =
          isViableIndirectTarget(rawFirstTarget, filteredFirstTarget);
      const bool secondViable =
          isViableIndirectTarget(rawSecondTarget, filteredSecondTarget);
      if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
        std::cout << "[diag] solvePath filter current=0x1400237f9 rawFirst=0x"
                  << std::hex << rawFirstTarget << " rawSecond=0x"
                  << rawSecondTarget << " first=0x" << filteredFirstTarget
                  << " second=0x" << filteredSecondTarget << std::dec
                  << " firstViable=" << firstViable
                  << " secondViable=" << secondViable << "\n";
      }
      if (firstViable != secondViable) {
        auto* selectInst = dyn_cast<SelectInst>(simplifyValue);
        if (selectInst) {
          llvm::Value* branchCondition = selectInst->getCondition();
          bool trueGoesToViable =
              firstViable
                  ? (selectInst->getTrueValue() == builder->getIntN(
                        simplifyValue->getType()->getIntegerBitWidth(),
                        pv[0].getZExtValue()))
                  : (selectInst->getTrueValue() == builder->getIntN(
                        simplifyValue->getType()->getIntegerBitWidth(),
                        pv[1].getZExtValue()));
          dest = firstViable ? filteredFirstTarget : filteredSecondTarget;
          result = PATH_solved;
          auto resolved = resolveTargetBlock(dest, "bb_filtered");
          auto* trueBlock = trueGoesToViable ? resolved.block : liftAbortBlock;
          auto* falseBlock = trueGoesToViable ? liftAbortBlock : resolved.block;
          auto* br = builder->CreateCondBr(branchCondition, trueBlock, falseBlock);
          RegisterBranch(br);
          if (!resolved.reusedBackedge) {
            blockInfo = BBInfo(dest, resolved.block);
            printvalue2("pushing block");
            backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
            unvisitedBlocks.push_back(blockInfo);
          }
          return result;
        }
        dest = firstViable ? filteredFirstTarget : filteredSecondTarget;
        result = PATH_solved;
        auto resolved = resolveTargetBlock(dest, "bb_filtered");
        builder->CreateBr(resolved.block);
        if (!resolved.reusedBackedge) {
          blockInfo = BBInfo(dest, resolved.block);
          printvalue2("pushing block");
          backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
          unvisitedBlocks.push_back(blockInfo);
        }
        return result;
      }
    }

    // auto bb_false = BasicBlock::Create(function->getContext(), "bb_false",
    //                                    builder->GetInsertBlock()->getParent());
    // auto bb_true = BasicBlock::Create(function->getContext(), "bb_true",
    //                                   builder->GetInsertBlock()->getParent());

    auto firstcase = pv[0];
    auto secondcase = pv[1];

    auto try_simplify = [&](APInt c1,
                                   Value* simplifyv) -> std::optional<Value*> {
      if (auto si = dyn_cast<SelectInst>(simplifyv)) {
        auto firstcase_v = builder->getIntN(
            simplifyv->getType()->getIntegerBitWidth(), c1.getZExtValue());
        if (si->getTrueValue() == firstcase_v) {
          printvalue(si);
          printvalue(firstcase_v);
          return si->getCondition();
        }
      }
      return std::nullopt;
    };

    Value* condition = nullptr;

    // condition value is a kind of hack
    // 1- if its a select, we can extract the condition
    // 1a- if firstcase is in the select, extract the condition
    // 1b- if secondcase is in the select, extract the condition and reverse
    // values
    // 2- create a hacky compare for condition == potentialvalue

    printvalue2(firstcase);
    printvalue2(secondcase);

    if (auto can_simplify = try_simplify(firstcase, simplifyValue)) {
      printvalue2("b");
      condition = can_simplify.value();
    } else if (auto can_simplify2 = try_simplify(secondcase, simplifyValue)) {
      // TODO: fix?
      printvalue2("c");
      std::swap(firstcase, secondcase);
      condition = can_simplify2.value();
    } else {
      printvalue2("a");
      condition = createICMPFolder(
          llvm::CmpInst::ICMP_EQ, simplifyValue,
          builder->getIntN(simplifyValue->getType()->getIntegerBitWidth(),
                           firstcase.getZExtValue()));
    }

    printvalue2(firstcase);
    printvalue2(secondcase);
    const uint64_t firstTarget =
        normalizeTargetAddress(firstcase.getZExtValue());
    const uint64_t secondTarget =
        normalizeTargetAddress(secondcase.getZExtValue());
    auto trueTarget = resolveTargetBlock(firstTarget, "bb_true");
    auto falseTarget = resolveTargetBlock(secondTarget, "bb_false");
    auto* bb_true = trueTarget.block;
    auto* bb_false = falseTarget.block;
    printvalue(condition);
    auto BR = builder->CreateCondBr(condition, bb_true, bb_false);

    RegisterBranch(BR);

    printvalue2(firstcase);
    printvalue2(secondcase);
    blockInfo = BBInfo(secondTarget, bb_false);
    // for [this], we can assume condition is true
    // we can simplify any value tied to is dependent on condition,
    // and try to simplify any value calculates condition

    // for [newlifter], we can assume condition is false
    auto newblock = BBInfo(firstTarget, bb_true);

    // this->blockInfo = newblock;
    printvalue(condition);

    // lifters.push_back(newlifter);

    // Constant conditions are already resolved — only track assumptions
    // for instruction-produced conditions that need runtime disambiguation.
    if (auto* condInst = dyn_cast<Instruction>(condition)) {
      if (!falseTarget.reusedBackedge && blockInfo.block != liftAbortBlock) {
        assumptions[condInst] = 0;
        backupQueuedTarget(blockInfo.block, falseTarget.generalizedBackup);
        addUnvisitedAddr(blockInfo);
      }

      if (!trueTarget.reusedBackedge && newblock.block != liftAbortBlock) {
        this->assumptions[condInst] = 1;
        backupQueuedTarget(newblock.block, trueTarget.generalizedBackup);
        addUnvisitedAddr(newblock);
      }
    } else {
      // Condition is a constant (e.g., from folded ICMP). Both branches
      // are statically determined — back them up without assumption state.
      if (!falseTarget.reusedBackedge && blockInfo.block != liftAbortBlock) {
        backupQueuedTarget(blockInfo.block, falseTarget.generalizedBackup);
        addUnvisitedAddr(blockInfo);
      }
      if (!trueTarget.reusedBackedge && newblock.block != liftAbortBlock) {
        backupQueuedTarget(newblock.block, trueTarget.generalizedBackup);
        addUnvisitedAddr(newblock);
      }
    }

    debugging::doIfDebug([&]() {
      std::string Filename = "output_newpath.ll";
      std::error_code EC;
      llvm::raw_fd_ostream OS(Filename, EC);
      function->getParent()->print(OS, nullptr);
      std::cout << "created a new path\n" << std::flush;
    });
  }

  if (pv.size() > 2) {
    // N-way branch: emit SwitchInst for multi-target resolution.
    // Default must stay unresolved because computePossibleValues() is heuristic.
    unsigned bitWidth = simplifyValue->getType()->getIntegerBitWidth();

    auto* bb_default_unresolved =
        createBudgetedBasicBlock("bb_switch_default_unresolved", current_address);
    if (bb_default_unresolved == liftAbortBlock) {
      builder->CreateRet(UndefValue::get(function->getReturnType()));
      return PATH_unsolved;
    }
    DTU->applyUpdates(
        {{DominatorTree::Insert, this->blockInfo.block, bb_default_unresolved}});

    auto* SI = builder->CreateSwitch(
        simplifyValue, bb_default_unresolved, static_cast<unsigned>(pv.size()));

    // Add every discovered target as an explicit case.
    std::set<uint64_t> emittedTargets;
    size_t switchCaseIndex = 0;
    for (const auto& caseVal : pv) {
      // computePossibleValues can emit a raw zero when it cross-products a
      // select whose unreachable branch defaults to 0.  That zero has no
      // relationship to any real control-flow target; passing it through
      // normalizeTargetAddress would re-emit `file.imageBase` as a bogus
      // switch case.  Drop the raw zero before we normalize.
      const uint64_t rawTarget = caseVal.getZExtValue();
      if (rawTarget == 0) {
        continue;
      }
      const uint64_t normalizedTarget = normalizeTargetAddress(rawTarget);
      if (!emittedTargets.insert(normalizedTarget).second) {
        continue;
      }

      // computePossibleValues cross-products uncorrelated select branches,
      // which can produce spurious targets outside mapped memory.  Skip them
      // rather than crashing when the lifter tries to decode bytes there.
      if (!isMemPaged(normalizedTarget)) {
        std::cout << "[diag] skipping unmapped switch target 0x"
                  << std::hex << normalizedTarget << std::dec << "\n"
                  << std::flush;
        continue;
      }

      auto bb_case = getOrCreateBB(
          normalizedTarget, "bb_switch_" + std::to_string(switchCaseIndex++));
      SI->addCase(
          cast<ConstantInt>(builder->getIntN(bitWidth, normalizedTarget)),
          bb_case);

      auto caseBlock = BBInfo(normalizedTarget, bb_case);
      addUnvisitedAddr(caseBlock);
      branch_backup(caseBlock.block);
    }

    // Conservative fallback for values not enumerated in pv:
    // keep default path data-dependent instead of returning undef, which can
    // let later optimizations fold valid cases into arbitrary constants.
    llvm::IRBuilder<> defaultBuilder(bb_default_unresolved);
    Value* unresolvedRet = simplifyValue;
    if (unresolvedRet->getType() != function->getReturnType()) {
      if (unresolvedRet->getType()->isIntegerTy() &&
          function->getReturnType()->isIntegerTy()) {
        unresolvedRet = defaultBuilder.CreateZExtOrTrunc(
            unresolvedRet, function->getReturnType(),
            "switch_default_unresolved");
      } else {
        unresolvedRet = UndefValue::get(function->getReturnType());
      }
    }
    defaultBuilder.CreateRet(unresolvedRet);
    // Destination remains unknown for multi-target switches.
    dest = 0;
    result = PATH_multi_solved;

    debugging::doIfDebug([&]() {
      std::string Filename = "output_switch.ll";
      std::error_code EC;
      llvm::raw_fd_ostream OS(Filename, EC);
      function->getParent()->print(OS, nullptr);
      std::cout << "created multi-target switch with " << emittedTargets.size()
                << " targets\n"
                << std::flush;
    });
  }

  if (pv.empty()) {
    // computePossibleValues exhausted its budget without resolving any
    // concrete targets.  Emit an undef-return sentinel so the block has a
    // valid terminator; do NOT use unreachable, which would let LLVM erase
    // this reachable-but-unresolved path.
    builder->CreateRet(UndefValue::get(function->getReturnType()));
  }

  return result;
}
