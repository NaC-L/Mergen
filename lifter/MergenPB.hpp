
#include "CustomPasses.hpp"
#include "lifterClass.hpp"
#include "utils.h"
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

// not pathsolver, & probably put this in lifter class, & we would utilize
// templates since geploadpass
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::run_opts() {
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

  llvm::Module* module = this->fnc->getParent();
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

    modulePassManager.addPass(GEPLoadPass(fnc->getArg(fnc->arg_size()),
                                          this->fileBase, memoryPolicy));
    modulePassManager.addPass(ReplaceTruncWithLoadPass());
    modulePassManager.addPass(
        PromotePseudoStackPass(fnc->getArg(fnc->arg_size())));
    modulePassManager.addPass(
        PromotePseudoMemory(fnc->getArg(fnc->arg_size())));

    modulePassManager.run(*module, moduleAnalysisManager);

    const size_t afterSize = module->getInstructionCount();

    changed = beforeSize != afterSize;

  } while (changed);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);

  modulePassManager.run(*module, moduleAnalysisManager);
}
