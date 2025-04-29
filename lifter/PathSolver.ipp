#pragma once

#include "PathSolver.h"
#include "lifterClass.hpp"
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

MERGEN_LIFTER_DEFINITION_TEMPLATES(PATH_info)::solvePath(
    llvm::Function* function, uint64_t& dest, Value* simplifyValue) {
  PATH_info result = PATH_unsolved;
  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplifyValue)) {
    dest = constInt->getZExtValue();
    result = PATH_solved;
    run = 0;
    auto bb_solved = BasicBlock::Create(
        function->getContext(), "bb_constraint-" + std::to_string(dest) + "-",
        builder.GetInsertBlock()->getParent());

    builder.CreateBr(bb_solved);
    blockInfo = BBInfo(dest, bb_solved);
    return result;
  }

  if (PATH_info solved = getConstraintVal(function, simplifyValue, dest)) {
    if (solved == PATH_solved) {
      run = 0;
      std::cout << "Solved the constraint and moving to next path\n"
                << std::flush;
      auto bb_solved = BasicBlock::Create(
          function->getContext(), "bb_constraint-" + std::to_string(dest) + "-",
          builder.GetInsertBlock()->getParent());

      builder.CreateBr(bb_solved);
      blockInfo = BBInfo(dest, bb_solved);
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
    auto bb_solved = BasicBlock::Create(function->getContext(), "bb_false",
                                        builder.GetInsertBlock()->getParent());

    builder.CreateBr(bb_solved);
    blockInfo = BBInfo(pv[0].getZExtValue(), bb_solved);
  }
  if (pv.size() == 2) {
    auto bb_false = BasicBlock::Create(function->getContext(), "bb_false",
                                       builder.GetInsertBlock()->getParent());
    auto bb_true = BasicBlock::Create(function->getContext(), "bb_true",
                                      builder.GetInsertBlock()->getParent());

    auto firstcase = pv[0];
    auto secondcase = pv[1];

    static auto try_simplify = [&](APInt c1,
                                   Value* simplifyv) -> std::optional<Value*> {
      if (auto si = dyn_cast<SelectInst>(simplifyv)) {
        auto firstcase_v = builder.getIntN(
            simplifyv->getType()->getIntegerBitWidth(), c1.getZExtValue());
        if (si->getTrueValue() == firstcase_v)
          return si->getCondition();
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

    if (auto can_simplify = try_simplify(firstcase, simplifyValue))
      condition = can_simplify.value();
    else if (auto can_simplify2 = try_simplify(secondcase, simplifyValue)) {
      std::swap(firstcase, secondcase);
      condition = can_simplify2.value();
    } else
      condition = createICMPFolder(
          llvm::CmpInst::ICMP_EQ, simplifyValue,
          builder.getIntN(simplifyValue->getType()->getIntegerBitWidth(),
                          firstcase.getZExtValue()));
    printvalue(condition);
    auto BR = builder.CreateCondBr(condition, bb_true, bb_false);

    RegisterBranch(BR);

    printvalue2(firstcase);
    printvalue2(secondcase);
    blockInfo = BBInfo(secondcase.getZExtValue(), bb_false);
    // for [this], we can assume condition is true
    // we can simplify any value tied to is dependent on condition,
    // and try to simplify any value calculates condition

    lifterClass* newlifter = new lifterClass(*this);

    // for [newlifter], we can assume condition is false
    newlifter->blockInfo = BBInfo(firstcase.getZExtValue(), bb_true);
    printvalue(condition);
    newlifter->assumptions[cast<Instruction>(condition)] = 1;

    assumptions[cast<Instruction>(condition)] = 0;

    lifters.push_back(newlifter);

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