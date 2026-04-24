
#include "CustomPasses.hpp"
#include "LifterClass.hpp"
#include "Utils.h"
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Transforms/IPO/DeadArgumentElimination.h>

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
  //   const char* a = "-jump-threading-across-loop-headers=1";
  //   llvm::cl::ParseCommandLineOptions(1, &a);

  do {
    changed = false;

    const size_t beforeSize = module->getInstructionCount();

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);

    llvm::Value* memoryArg = this->memoryAlloc;
    if (!memoryArg) {
      llvm::report_fatal_error(
          "run_opts: memoryAlloc is null; lifter setup did not initialize it");
    }

    modulePassManager.addPass(
        GEPLoadPass(memoryArg, this->fileBase, memoryPolicy, this->stackReserve));
    modulePassManager.addPass(ReplaceTruncWithLoadPass());
    modulePassManager.addPass(PromotePseudoStackPass(memoryArg, this->stackReserve));
    modulePassManager.addPass(PromotePseudoMemory(memoryArg));

    modulePassManager.run(*module, moduleAnalysisManager);

    const size_t afterSize = module->getInstructionCount();

    changed = beforeSize != afterSize;
  } while (changed);

  // Rebuild analysis state before the final O2 pipeline. The fixpoint loop above
  // mutates the module repeatedly with custom passes; fresh managers keep the
  // final optimization run aligned with standalone `opt -O2` on output_no_opts.ll.
  llvm::LoopAnalysisManager finalLoopAnalysisManager;
  llvm::FunctionAnalysisManager finalFunctionAnalysisManager;
  llvm::CGSCCAnalysisManager finalCGSCCAnalysisManager;
  llvm::ModuleAnalysisManager finalModuleAnalysisManager;

  passBuilder.registerModuleAnalyses(finalModuleAnalysisManager);
  passBuilder.registerCGSCCAnalyses(finalCGSCCAnalysisManager);
  passBuilder.registerFunctionAnalyses(finalFunctionAnalysisManager);
  passBuilder.registerLoopAnalyses(finalLoopAnalysisManager);
  passBuilder.crossRegisterProxies(finalLoopAnalysisManager,
                                   finalFunctionAnalysisManager,
                                   finalCGSCCAnalysisManager,
                                   finalModuleAnalysisManager);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);

  modulePassManager.run(*module, finalModuleAnalysisManager);

  // Post-optimization passes: normalize IR, drop dead parameters, canonicalize names.
  llvm::ModulePassManager postPassManager;
  postPassManager.addPass(StripTrailingScratchStoresPass());
  postPassManager.addPass(SelectChainToSwitchPass());
  postPassManager.addPass(SwitchNormalizationPass());
  postPassManager.addPass(llvm::DeadArgumentEliminationPass());
  postPassManager.addPass(CanonicalNamingPass());
  postPassManager.run(*module, finalModuleAnalysisManager);
}
