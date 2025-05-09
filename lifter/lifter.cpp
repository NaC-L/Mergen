
#include "fileReader.hpp"
#define MAGIC_ENUM_RANGE_MIN -1000
#define MAGIC_ENUM_RANGE_MAX 1000

#include "CommonMnemonics.h"
#include "CommonRegisters.h"
#include "FunctionSignatures.hpp"
#include "GEPTracker.h"
#include "PathSolver.h"
#include "ZydisDisassembler.hpp"
#include "icedDisassembler.hpp"
#include "includes.h"
#include "lifterClass.hpp"
#include "nt/nt_headers.hpp"

// #include "test_instructions.h"
#include "utils.h"
#include <coff/line_number.hpp>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/LazyCallGraph.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/IRBuilderFolder.h>
#include <llvm/Support/NativeFormatting.h>
#include <magic_enum/magic_enum.hpp>

#include "Semantics.ipp"

// #define TEST
std::vector<lifterClass<>*> lifters;
uint64_t original_address = 0;
unsigned int pathNo = 0;
// consider having this function in a class, later we can use multi-threading to
// explore different paths
unsigned int breaking = 0;
arch_mode is64Bit;

void asm_to_zydis_to_lift(std::vector<uint8_t>& fileData) {

  auto data = fileData.data();

  auto lifter = lifters.back();
  BBInfo bbinfo;

  while (lifter->getUnvisitedAddr(bbinfo)) {
    lifter->load_backup(bbinfo);
    lifter->finished = 0;
    auto next_bb_name = bbinfo.block->getName();
    printvalue2(next_bb_name);
    lifter->builder.SetInsertPoint(bbinfo.block);
    lifter->liftBasicBlockFromAddress(bbinfo.block_address);
  }
  // Initialize the context structure

  // while (lifters.size() > 0) {
  //   auto lifter = lifters.back();

  //   lifter->current_address = lifter->blockInfo.block_address;
  //   lifter->builder.SetInsertPoint(lifter->blockInfo.block);

  //   lifter->run = 1;
  //   while ((lifter->run && !lifter->finished)) {

  //     // ZydisDecodedInstruction instruction;
  //     /*
  //           if
  //           (BinaryOperations::isWrittenTo(lifter->blockInfo.block_address))
  //        { printvalueforce2(lifter->blockInfo.block_address);
  //        UNREACHABLE("Found Self Modifying Code! we dont support it");
  //           }
  //      */
  //     auto counter = debugging::increaseInstCounter() - 1;
  //     /*
  //     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  //      ZydisDecoderDecodeFull(&decoder, data + offset, 15, &(instruction),
  //                             operands);

  //      debugging::doIfDebug([&]() {
  //        ZydisFormatter formatter;

  //        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
  //        char buffer[256];
  //        ZyanU64 runtime_address = 0;
  //        ZydisFormatterFormatInstruction(
  //            &formatter, &(instruction), operands,
  //            lifter->instruction.operand_count_visible, &buffer[0],
  //            sizeof(buffer), runtime_address, ZYAN_NULL);
  //        const auto ct = (llvm::format_hex_no_prefix(lifter->counter, 0));
  //        printvalue2(ct);
  //        const auto inst = buffer;
  //        printvalue2(inst);
  //        const auto runtime = lifter->blockInfo.runtime_address;
  //        printvalue2(runtime);
  //      });
  //      */

  //     printvalue2(lifter->current_address);
  //     lifter->liftAddress(lifter->current_address);

  //     /*   lifter->runDisassembler(data + offset);
  //       lifter->current_address += lifter->instruction.length;
  //       lifter->liftInstruction(); */

  //     printvalue2(lifter->finished);
  //     if (lifter->finished) {
  //       lifter->run = 0;
  //       lifters.pop_back();

  //       debugging::doIfDebug([&]() {
  //         std::string Filename =
  //             "output_path_" + std::to_string(++pathNo) + ".ll";
  //         std::error_code EC;
  //         llvm::raw_fd_ostream OS(Filename, EC);
  //         lifter->fnc->getParent()->print(OS, nullptr);
  //       });
  //       auto nextlift = "next lifter instance\n";
  //       printvalue2(nextlift);

  //       delete lifter;
  //       break;
  //     }
  //   }
  //}
}

void InitFunction_and_LiftInstructions(const uint64_t runtime_address,
                                       std::vector<uint8_t> fileData) {

  auto fileBase = fileData.data();
  llvm::LLVMContext context;
  std::string mod_name = "my_lifting_module";
  llvm::Module lifting_module = llvm::Module(mod_name.c_str(), context);

  std::vector<llvm::Type*> argTypes;
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::Type::getInt64Ty(context));
  argTypes.push_back(llvm::PointerType::get(context, 0));
  argTypes.push_back(llvm::PointerType::get(context, 0)); // temp fix TEB

  auto functionType =
      llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes, 0);

  const std::string function_name = "main";
  auto function =
      llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                             function_name.c_str(), lifting_module);
  const std::string block_name = "entry";
  auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);

  llvm::InstSimplifyFolder Folder(lifting_module.getDataLayout());
  llvm::IRBuilder<llvm::InstSimplifyFolder> builder =
      llvm::IRBuilder<llvm::InstSimplifyFolder>(bb, Folder);

  // auto RegisterList = InitRegisters(builder, function, runtime_address);

  auto main = new lifterClass(builder, fileBase);
  // main->InitRegisters(function, runtime_address);
  main->blockInfo = BBInfo(runtime_address, bb);
  main->unvisitedBlocks.push_back(main->blockInfo);
  main->fnc = function;
  main->initDomTree(*function);
  main->loadFile(fileBase);
  x86FileReader file(fileBase);
  auto dosHeader = (win::dos_header_t*)fileBase;
  if (*(unsigned short*)fileBase != 0x5a4d) {
    UNREACHABLE("Only PE files are supported");
  }

  auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
  auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

  auto ntHeaders = (win::nt_headers_t<true>*)(fileBase + dosHeader->e_lfanew);
  auto PEmagic = ntHeaders->optional_header.magic;

  is64Bit = (arch_mode)(PEmagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

  auto processHeaders = [fileBase, runtime_address, &file,
                         main](const void* ntHeadersBase) -> uint64_t {
    uint64_t address, imageSize, stackSize;

    if (is64Bit) {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
      address = ntHeaders->optional_header.image_base;
      imageSize = ntHeaders->optional_header.size_image;
      stackSize = ntHeaders->optional_header.size_stack_reserve;
    } else {
      auto ntHeaders =
          reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
      address = ntHeaders->optional_header.image_base;
      imageSize = ntHeaders->optional_header.size_image;
      stackSize = ntHeaders->optional_header.size_stack_reserve;
    }

    const uint64_t RVA = static_cast<uint64_t>(runtime_address - address);
    const uint64_t fileOffset = file.RvaToFileOffset(RVA);
    const uint8_t* dataAtAddress =
        reinterpret_cast<const uint8_t*>(fileBase) + fileOffset;

    std::cout << std::hex << "0x" << static_cast<int>(*dataAtAddress)
              << std::endl;

    std::cout << "address: " << address << " imageSize: " << imageSize
              << " filebase: " << reinterpret_cast<uint64_t>(fileBase)
              << " fOffset: " << fileOffset << " RVA: " << RVA
              << " stackSize: " << stackSize << std::endl;

    main->markMemPaged(STACKP_VALUE - stackSize, STACKP_VALUE + stackSize);
    printvalue2(stackSize);
    main->markMemPaged(address, address + imageSize);
    return imageSize;
  };

  original_address = processHeaders(fileBase + dosHeader->e_lfanew);

  main->signatures.search_signatures(fileData);
  main->signatures.createOffsetMap(); // ?
  for (const auto& [key, value] : main->signatures.siglookup) {
    value.display();
  }

  auto ms = timer::getTimer();
  std::cout << "\n" << std::dec << ms << " milliseconds has past" << std::endl;

  // main->liftBasicBlockFromAddress(0x1400011C7);
  // main->writeFunctionToFile("test.ll");
  // printvalue2("liftbasicBLOCk");

  // blockAddresses->push_back(make_tuple(runtime_address, bb,
  // RegisterList));
  lifters.push_back(main);

  asm_to_zydis_to_lift(fileData);

  ms = timer::getTimer();

  std::cout << "\nlifting complete, " << std::dec << ms
            << " milliseconds has past" << std::endl;

  main->writeFunctionToFile("output_no_opts.ll");
  /* const std::string Filename_noopt = "output_no_opts.ll";
std::error_code EC_noopt;
llvm::raw_fd_ostream OS_noopt(Filename_noopt, EC_noopt);

lifting_module.print(OS_noopt, nullptr);

*/
  std::cout << "\nwriting complete, " << std::dec << ms
            << " milliseconds has past" << std::endl;

  final_optpass(function, function->getArg(17), fileData.data());
  const std::string Filename = "output.ll";
  std::error_code EC;
  llvm::raw_fd_ostream OS(Filename, EC);

  lifting_module.print(OS, nullptr);

  return;
}

// #define TEST

int main(int argc, char* argv[]) {

  std::vector<std::string> args(argv, argv + argc);
  argparser::parseArguments(args);
  timer::startTimer();

#ifdef MERGEN_TEST
  if (1 == 1)
    return testInit(args[1]);
#endif
  // use parser
  if (args.size() < 3) {
    std::cerr << "Usage: " << args[0] << " <filename> <startAddr>" << std::endl;
    return 1;
  }

  // debugging::enableDebug();

  const char* filename = args[1].c_str();
  uint64_t startAddr = stoull(args[2], nullptr, 0);

  std::ifstream ifs(filename, std::ios::binary);
  if (!ifs.is_open()) {
    std::cout << "Failed to open the file." << std::endl;
    return 1;
  }

  ifs.seekg(0, std::ios::end);
  std::vector<uint8_t> fileData(ifs.tellg());
  ifs.seekg(0, std::ios::beg);

  if (!ifs.read((char*)fileData.data(), fileData.size())) {
    std::cout << "Failed to read the file." << std::endl;
    return 1;
  }
  ifs.close();

  InitFunction_and_LiftInstructions(startAddr, fileData);
  auto milliseconds = timer::stopTimer();
  std::cout << "\n"
            << std::dec << milliseconds << " milliseconds has past"
            << std::endl;
  std::cout << "Lifted and optimized " << debugging::increaseInstCounter() - 1
            << " total insts";
}
