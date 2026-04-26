
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
  // Cap fixpoint iterations to prevent unbounded loops if a pair of passes
  // ever oscillates. 64 is well above any value observed in practice.
  constexpr unsigned kMaxFixpointIterations = 64;

  fixpointStats.initial_size = module->getInstructionCount();

  llvm::Value* memoryArg = this->memoryAlloc;
  if (!memoryArg) {
    llvm::report_fatal_error(
        "run_opts: memoryAlloc is null; lifter setup did not initialize it");
  }

  unsigned iter = 0;
  bool changed = false;
  do {
    using clock = std::chrono::high_resolution_clock;
    auto iterStart = clock::now();

    FixpointIteration record{};
    record.iteration = iter;
    record.before = module->getInstructionCount();

    // O1 bundle.
    {
      auto t = clock::now();
      llvm::ModulePassManager pm =
          passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);
      pm.run(*module, moduleAnalysisManager);
      record.o1_ms = std::chrono::duration<double, std::milli>(clock::now() - t).count();
    }
    record.after_o1 = module->getInstructionCount();

    // Custom passes split out individually so per-pass deltas are observable.
    {
      auto t = clock::now();
      llvm::ModulePassManager pm;
      pm.addPass(GEPLoadPass(memoryArg, this->fileBase, memoryPolicy, this->stackReserve));
      pm.run(*module, moduleAnalysisManager);
      record.geploadpass_ms = std::chrono::duration<double, std::milli>(clock::now() - t).count();
    }
    record.after_geploadpass = module->getInstructionCount();

    {
      auto t = clock::now();
      llvm::ModulePassManager pm;
      pm.addPass(ReplaceTruncWithLoadPass());
      pm.run(*module, moduleAnalysisManager);
      record.replacetrunc_ms = std::chrono::duration<double, std::milli>(clock::now() - t).count();
    }
    record.after_replacetrunc = module->getInstructionCount();

    {
      auto t = clock::now();
      llvm::ModulePassManager pm;
      pm.addPass(PromotePseudoStackPass(memoryArg, this->stackReserve));
      pm.run(*module, moduleAnalysisManager);
      record.promotestack_ms = std::chrono::duration<double, std::milli>(clock::now() - t).count();
    }
    record.after_promotestack = module->getInstructionCount();

    {
      auto t = clock::now();
      llvm::ModulePassManager pm;
      pm.addPass(PromotePseudoMemory(memoryArg));
      pm.run(*module, moduleAnalysisManager);
      record.promotemem_ms = std::chrono::duration<double, std::milli>(clock::now() - t).count();
    }
    record.after_promotemem = module->getInstructionCount();

    record.ms = std::chrono::duration<double, std::milli>(clock::now() - iterStart).count();
    fixpointStats.iteration_log.push_back(record);

    changed = record.before != record.after_promotemem;
    ++iter;

    if (iter >= kMaxFixpointIterations && changed) {
      fixpointStats.reached_cap = true;
      diagnostics.warning(DiagCode::FixpointMaxIterations, 0,
          "run_opts: fixpoint did not converge within " +
          std::to_string(kMaxFixpointIterations) + " iterations; bailing out");
      break;
    }
  } while (changed);

  fixpointStats.iterations = iter;
  fixpointStats.final_loop_size = module->getInstructionCount();
  if (!fixpointStats.reached_cap) {
    diagnostics.info(DiagCode::FixpointConverged, 0,
        "run_opts: fixpoint converged after " + std::to_string(iter) + " iteration(s)");
  }

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
  fixpointStats.final_o2_size = module->getInstructionCount();

  // Post-optimization passes: normalize IR, drop dead parameters, canonicalize names.
  llvm::ModulePassManager postPassManager;
  postPassManager.addPass(StripTrailingScratchStoresPass());
  postPassManager.addPass(SelectChainToSwitchPass());
  postPassManager.addPass(SwitchNormalizationPass());
  postPassManager.addPass(llvm::DeadArgumentEliminationPass());
  postPassManager.addPass(CanonicalNamingPass());
  postPassManager.run(*module, finalModuleAnalysisManager);
  fixpointStats.final_post_size = module->getInstructionCount();
}
