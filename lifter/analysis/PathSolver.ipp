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
  auto normalizeTargetAddress = [&](uint64_t target) -> uint64_t {
    if (isMemPaged(target)) {
      return target;
    }

    if (target <= std::numeric_limits<uint32_t>::max() &&
        file.imageBase > std::numeric_limits<uint32_t>::max()) {
      const uint64_t highBits = file.imageBase & 0xFFFFFFFF00000000ULL;
      const uint64_t widened = highBits | target;
      if (isMemPaged(widened)) {
        return widened;
      }
    }

    return target;
  };

  struct ResolvedTargetBlock {
    BasicBlock* block;
    bool reusedBackedge;
    bool generalizedBackup;
  };

  auto resolveTargetBlock = [&](uint64_t target, const std::string& name)
      -> ResolvedTargetBlock {
    if (auto* reused = getLiftedBackedgeBB(target)) {
      return {reused, true, false};
    }

    const bool backwardVisitedTarget =
        visitedAddresses.contains(target) &&
        target <= blockInfo.block_address;
    auto it = addrToBB.find(target);
    const bool hasPendingGeneralization =
        pendingLoopGeneralizationAddresses.contains(target);
    const bool canUseStructuredLoopGeneralization =
        currentPathSolveAllowsStructuredLoopGeneralization();
    const bool canReusePendingGeneralization =
        hasPendingGeneralization && canUseStructuredLoopGeneralization;
    const bool wantsGeneralization =
        canReusePendingGeneralization ||
        (backwardVisitedTarget && canGeneralizeStructuredLoopHeader(target));
    if (wantsGeneralization) {
      if (currentPathSolveContext == PathSolveContext::DirectJump) {
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

  PATH_info result = PATH_unsolved;
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
      const uint64_t normalizedTarget =
          normalizeTargetAddress(caseVal.getZExtValue());
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
