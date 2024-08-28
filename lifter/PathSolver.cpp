#include "CustomPasses.hpp"
#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"
#include "lifterClass.h"
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>

void* file_base_g;
ZyanU8* data_g;

struct InstructionDependencyOrder {
  bool operator()(Instruction* const& a, Instruction* const& b) const {

    Function* F = a->getFunction();
    GEPStoreTracker::updateDomTree(*F);
    DominatorTree* DT = GEPStoreTracker::getDomTree();

    return (comesBefore(b, a, *DT));
  }
};

void lifterClass::replaceAllUsesWithandReplaceRMap(Value* v, Value* nv,
                                                   ReverseRegisterMap rVMap) {

  // if two values are same, we go in a infinite loop
  if (v == nv)
    return;

  auto registerV = rVMap[v];

  if (registerV) {
    if (isa<Instruction>(v)) {
      // auto registerI = cast<Instruction>(v);
      SetRegisterValue(registerV, v);
    }
  }

  v->replaceAllUsesWith(nv);

  // redundant?
  v = nv;

  // dont ask me this i dont know

  // users start from latest user
  std::vector<User*> users;
  for (auto& use : v->uses()) {
    users.push_back(use.getUser());
  }

  // iterate over the users in reverse order
  for (auto it = users.rbegin(); it != users.rend(); ++it) {
    User* user = *it;
    if (auto GEPuser = dyn_cast<GetElementPtrInst>(user)) {
      for (auto StoreUser : GEPuser->users()) {
        if (auto SI = dyn_cast<StoreInst>(StoreUser)) {
          GEPStoreTracker::updateMemoryOp(SI);
        }
      }
    }
  }
}

// simplify Users with BFS
// because =>
// x = add a, b
// if we go simplify a then simplify x, then simplify b, we might miss
// simplifying x if we go simplify a, then simplify b, then simplify x we will
// not miss
//
// also refactor this

PATH_info getConstraintVal(llvm::Function* function, Value* constraint,
                           uint64_t& dest) {
  PATH_info result = PATH_unsolved;
  printvalue(constraint);
  auto simplified_constraint = simplifyValue(
      constraint,
      function->getParent()->getDataLayout()); // this is such a hack
  printvalue(simplified_constraint);

  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplified_constraint)) {
    printvalue(constInt) dest = constInt->getZExtValue();
    result = PATH_solved;
    return result;
  }

  return result;
}

void final_optpass(Function* clonedFuncx) {
  llvm::PassBuilder passBuilder;

  llvm::LoopAnalysisManager loopAnalysisManager;
  llvm::FunctionAnalysisManager functionAnalysisManager;
  llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
  llvm::ModuleAnalysisManager moduleAnalysisManager;

  passBuilder.registerModuleAnalyses(moduleAnalysisManager);
  passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
  passBuilder.registerFunctionAnalyses(functionAnalysisManager);
  passBuilder.registerLoopAnalyses(loopAnalysisManager);
  passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager,
                                   cGSCCAnalysisManager, moduleAnalysisManager);

  llvm::ModulePassManager modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);

  llvm::Module* module = clonedFuncx->getParent();

  bool changed;
  do {
    changed = false;

    size_t beforeSize = module->getInstructionCount();

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    modulePassManager.addPass(GEPLoadPass());
    modulePassManager.addPass(ReplaceTruncWithLoadPass());
    modulePassManager.addPass(PromotePseudoStackPass());

    modulePassManager.run(*module, moduleAnalysisManager);

    size_t afterSize = module->getInstructionCount();

    if (beforeSize != afterSize) {

      changed = true;
    }

  } while (changed);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

  modulePassManager.addPass(ResizeAllocatedStackPass());
  modulePassManager.addPass(PromotePseudoMemory());

  modulePassManager.run(*module, moduleAnalysisManager);
}

llvm::ValueToValueMapTy* flipVMap(const ValueToValueMapTy& VMap) {

  ValueToValueMapTy* RevMap = new llvm::ValueToValueMapTy;
  for (const auto& pair : VMap) {
    (*RevMap)[pair.second] = const_cast<Value*>(pair.first);
  }
  return RevMap;
}

PATH_info lifterClass::solvePath(Function* function, uint64_t& dest,
                                 Value* simplifyValue) {

  PATH_info result = PATH_unsolved;
  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplifyValue)) {
    dest = constInt->getZExtValue();
    result = PATH_solved;
    run = 0;
    auto bb_solved = BasicBlock::Create(function->getContext(), "bb_constraint",
                                        builder.GetInsertBlock()->getParent());

    builder.CreateBr(bb_solved);
    blockInfo = make_tuple(dest, bb_solved, getRegisters());
    return result;
  }

  if (PATH_info solved = getConstraintVal(function, simplifyValue, dest)) {
    if (solved == PATH_solved) {
      run = 0;
      outs() << "Solved the constraint and moving to next path\n";
      outs().flush();
      auto bb_solved =
          BasicBlock::Create(function->getContext(), "bb_constraint",
                             builder.GetInsertBlock()->getParent());

      builder.CreateBr(bb_solved);
      blockInfo = make_tuple(dest, bb_solved, getRegisters());
      return solved;
    }
  }

  // unsolved
  printvalue(simplifyValue);
  run = 0;
  auto pvset = GEPStoreTracker::computePossibleValues(simplifyValue);
  vector<APInt> pv(pvset.begin(), pvset.end());
  for (auto vv : pv) {
    printvalue2(vv);
  }
  if (pv.size() == 1) {
    printvalue2(pv[0]);
    auto bb_solved = BasicBlock::Create(function->getContext(), "bb_false",
                                        builder.GetInsertBlock()->getParent());

    builder.CreateBr(bb_solved);
    blockInfo = make_tuple(pv[0].getZExtValue(), bb_solved, getRegisters());
  }
  if (pv.size() == 2) {
    auto bb_false = BasicBlock::Create(function->getContext(), "bb_false",
                                       builder.GetInsertBlock()->getParent());
    auto bb_true = BasicBlock::Create(function->getContext(), "bb_true",
                                      builder.GetInsertBlock()->getParent());
    auto firstcase = pv[0];
    auto secondcase = pv[1];

    static auto try_simplify = [&](APInt c1, Value* simplifyv) -> optional<Value*> {
        
      if (auto si = dyn_cast<SelectInst>(simplifyv)) {
        auto firstcase_v = builder.getIntN(
            simplifyv->getType()->getIntegerBitWidth(), c1.getZExtValue());
        if (si->getTrueValue() == firstcase_v)
          return si->getCondition();
      }
      return nullopt;
    };

    Value* condition = nullptr;
    if (auto can_simplify = try_simplify(firstcase, simplifyValue))
      condition = can_simplify.value();
    else if (auto can_simplify2 = try_simplify(secondcase, simplifyValue)) {
      swap(firstcase, secondcase);
      condition = can_simplify2.value();
    } else
      condition = createICMPFolder(
          builder, CmpInst::ICMP_EQ, simplifyValue,
          builder.getIntN(simplifyValue->getType()->getIntegerBitWidth(),
                          firstcase.getZExtValue()));
    printvalue(condition);
    auto BR = builder.CreateCondBr(condition, bb_false, bb_true);

    GetSimplifyQuery::RegisterBranch(BR);
    blockInfo = make_tuple(secondcase.getZExtValue(), bb_true, getRegisters());

    lifterClass* newlifter = new lifterClass(builder);

    newlifter->blockInfo =
        make_tuple(firstcase.getZExtValue(), bb_false, getRegisters());

    lifters.push_back(newlifter);
    outs() << "created a new path\n";
  }
  if (pv.size() > 2) {
    llvm_unreachable_internal("cant reach more than 2 paths!");
  }

  return result;
}