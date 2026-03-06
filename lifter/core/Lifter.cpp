
#define MAGIC_ENUM_RANGE_MIN -1000
#define MAGIC_ENUM_RANGE_MAX 1000

#include "CommandLineHelpers.hpp"
#include "LifterApplication.hpp"
#include "LifterPipeline.hpp"
#include "LifterStages.hpp"
#include "MergenPB.hpp"
#include "Includes.h"
#include "LifterClass.hpp"
#include "LifterClass_Concolic.hpp"
#include "LifterClass_Symbolic.hpp"


#include "TestInstructions.h"
#include "Semantics.ipp"
#include "Utils.h"
#include <coff/line_number.hpp>
#include <cstdint>
#include <iostream>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/LazyCallGraph.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/IRBuilderFolder.h>
#include <llvm/Support/NativeFormatting.h>
#include <magic_enum/magic_enum.hpp>

// #define TEST



void InitFunction_and_LiftInstructions(const uint64_t runtime_address,
                                       std::vector<uint8_t> fileData) {

  auto stageContext = prepareLifterStageContext(runtime_address, fileData);
  runLifterPipeline(stageContext.lifter.get(), stageContext.runtimeContext,
                    fileData.data(), fileData);
  return;
}

// #define TEST
int main(int argc, char* argv[]) {
  std::vector<std::string> args(argv, argv + argc);
  argparser::parseArguments(args);
  timer::startTimer();

#ifdef MERGEN_TEST
  if (args.size() > 1 &&
      (args[1] == "--build-full-seed" || args[1] == "build-full-seed")) {
    const std::string outputPath =
        args.size() > 2 ? args[2] : "scripts/rewrite/oracle_seed_full_handlers.json";
    uint64_t maxAttempts = 2'500'000;
    uint64_t randomSeed = 1337;
    try {
      if (args.size() > 3) {
        maxAttempts = std::stoull(args[3], nullptr, 0);
      }
      if (args.size() > 4) {
        randomSeed = std::stoull(args[4], nullptr, 0);
      }
    } catch (const std::exception& ex) {
      std::cerr << "Invalid build-full-seed numeric arguments: " << ex.what()
                << std::endl;
      return 1;
    }

    return buildFullHandlerSeed(outputPath, "lifter/semantics/x86_64_opcodes.x", maxAttempts,
                                randomSeed);
  }

  const std::string suiteFilter = args.size() > 1 ? args[1] : "";
  return testInit(suiteFilter);
#endif
  return runLifterApplication(args, InitFunction_and_LiftInstructions);
}
