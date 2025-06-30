#pragma once

#include "CommonDisassembler.hpp"
#include "PathSolver.h"
#include "lifterClass.hpp"
#include "utils.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/Analysis/MemorySSAUpdater.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>

MERGEN_LIFTER_DEFINITION_TEMPLATES(PATH_info)::solvePath(
    llvm::Function* function, uint64_t& dest, Value* simplifyValue) {

  // do static polymorphism here

  PATH_info result = PATH_unsolved;
  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplifyValue)) {
    dest = constInt->getZExtValue();
    result = PATH_solved;
    run = 0;

    auto bb_solved = getOrCreateBB(dest, "bb_solved_const");

    builder->CreateBr(bb_solved);
    blockInfo = BBInfo(dest, bb_solved);
    printvalue2("pushing block");
    unvisitedBlocks.push_back(blockInfo);

    return result;
  }

  if (PATH_info solved = getConstraintVal(function, simplifyValue, dest)) {
    if (solved == PATH_solved) {
      run = 0;
      std::cout << "Solved the constraint and moving to next path\n"
                << std::flush;

      auto bb_solved = getOrCreateBB(dest, "bb_solved");

      builder->CreateBr(bb_solved);
      blockInfo = BBInfo(dest, bb_solved);
      printvalue2("pushing block");
      unvisitedBlocks.push_back(blockInfo);

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
    /*
    auto bb_solved = BasicBlock::Create(function->getContext(), "bb_false",
                                        builder->GetInsertBlock()->getParent());
    */

    auto bb_solved = getOrCreateBB(pv[0].getZExtValue(), "bb_single");
    builder->CreateBr(bb_solved);
    blockInfo = BBInfo(pv[0].getZExtValue(), bb_solved);
    printvalue2("pushing block");
    unvisitedBlocks.push_back(blockInfo);
  }
  if (pv.size() == 2) {

    // auto bb_false = BasicBlock::Create(function->getContext(), "bb_false",
    //                                    builder->GetInsertBlock()->getParent());
    // auto bb_true = BasicBlock::Create(function->getContext(), "bb_true",
    //                                   builder->GetInsertBlock()->getParent());

    auto firstcase = pv[0];
    auto secondcase = pv[1];

    static auto try_simplify = [&](APInt c1,
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
    auto bb_true = getOrCreateBB(firstcase.getZExtValue(), "bb_true");
    auto bb_false = getOrCreateBB(secondcase.getZExtValue(), "bb_false");
    printvalue(condition);
    auto BR = builder->CreateCondBr(condition, bb_true, bb_false);

    RegisterBranch(BR);

    printvalue2(firstcase);
    printvalue2(secondcase);
    blockInfo = BBInfo(secondcase.getZExtValue(), bb_false);
    // for [this], we can assume condition is true
    // we can simplify any value tied to is dependent on condition,
    // and try to simplify any value calculates condition

    // for [newlifter], we can assume condition is false
    auto newblock = BBInfo(firstcase.getZExtValue(), bb_true);

    // this->blockInfo = newblock;
    printvalue(condition);

    // lifters.push_back(newlifter);

    // store mem&reg info for BB
    addUnvisitedAddr(blockInfo);
    addUnvisitedAddr(newblock);

    // fix this later, is ugly
    assumptions[cast<Instruction>(condition)] = 0;
    branch_backup(blockInfo.block);

    this->assumptions[cast<Instruction>(condition)] = 1;
    branch_backup(newblock.block);

    debugging::doIfDebug([&]() {
      std::string Filename = "output_newpath.ll";
      std::error_code EC;
      llvm::raw_fd_ostream OS(Filename, EC);
      function->getParent()->print(OS, nullptr);
    });
    std::cout << "created a new path\n" << std::flush;
  }

  if (pv.size() > 2) {
    UNREACHABLE("cant reach more than 2 paths!");
  }

  return result;
}
