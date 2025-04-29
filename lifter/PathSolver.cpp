
#include "CustomPasses.hpp"
#include "OperandUtils.h"
#include "lifterClass.hpp"
#include "utils.h"
#include <iostream>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

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
  /*
   auto simplified_constraint = simplifyValue(
       constraint,
       function->getParent()->getDataLayout()); // this is such a hack
       //
  printvalue(simplified_constraint);

  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplified_constraint)) {
    printvalue(constInt) dest = constInt->getZExtValue();
    result = PATH_solved;
    return result;
  }
  */

  return result;
}

void final_optpass(llvm::Function* clonedFuncx, Value* mem, uint8_t* filebase) {
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
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O0);

  llvm::Module* module = clonedFuncx->getParent();
  /*
  modulePassManager.addPass(BasicBlockDotGraphPass());

  modulePassManager.run(*module, moduleAnalysisManager);
  */
  bool changed = 0;
  do {
    changed = false;

    const size_t beforeSize = module->getInstructionCount();

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);

    modulePassManager.addPass(GEPLoadPass(mem, filebase));
    modulePassManager.addPass(ReplaceTruncWithLoadPass());
    modulePassManager.addPass(PromotePseudoStackPass(mem));

    modulePassManager.run(*module, moduleAnalysisManager);

    const size_t afterSize = module->getInstructionCount();

    changed = beforeSize != afterSize;

  } while (changed);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);

  modulePassManager.addPass(ResizeAllocatedStackPass());
  modulePassManager.addPass(PromotePseudoMemory());

  modulePassManager.run(*module, moduleAnalysisManager);
}
