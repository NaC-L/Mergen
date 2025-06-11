
#define MAGIC_ENUM_RANGE_MIN -1000
#define MAGIC_ENUM_RANGE_MAX 1000

#include "MemoryPolicy.hpp"
#include "MergenPB.hpp"
#include "PathSolver.h"
#include "ZydisDisassembler.hpp"
#include "fileReader.hpp"
#include "includes.h"
#include "lifterClass.hpp"
#include "lifterClass_concolic.hpp"
#include "lifterClass_symbolic.hpp"
#include "nt/nt_headers.hpp"


// #include "test_instructions.h"
#include "Semantics.ipp"
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

// #define TEST

uint64_t original_address = 0;
unsigned int pathNo = 0;
// consider having this function in a class, later we can use multi-threading to
// explore different paths
unsigned int breaking = 0;
arch_mode is64Bit;

void asm_to_zydis_to_lift(lifterConcolic<>* lifter,
                          std::vector<uint8_t>& fileData) {

  // auto data = fileData.data();

  BBInfo bbinfo;
  bool filter = 0;
  while (lifter->getUnvisitedAddr(bbinfo, filter)) {

    // printvalueforce2("exploring " + std::to_string(bbinfo.block_address));

    if (!(bbinfo.block->empty()) && filter) {
      printvalue2("not empty");
      continue;
    };

    filter = 1;
    lifter->load_backup(bbinfo.block);
    lifter->finished = 0;
    auto next_bb_name = bbinfo.block->getName();
    printvalue2(next_bb_name);
    lifter->builder->SetInsertPoint(bbinfo.block);

    lifter->liftBasicBlockFromAddress(bbinfo.block_address);
  }
}

void InitFunction_and_LiftInstructions(const uint64_t runtime_address,
                                       std::vector<uint8_t> fileData) {

  auto fileBase = fileData.data();

  auto main = new lifterConcolic<>();
  main->loadFile(fileBase);
  // configure memory policy - debug for now

  main->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& it : main->file.sections_v) {
    if (it.characteristics.mem_write) {
      // printvalue2(main->file.imageBase + it.virtual_address);
      // printvalue2(main->file.imageBase + it.virtual_address +
      // it.virtual_size); printvalue2("symbolic");
      main->memoryPolicy.addRange(main->file.imageBase + it.virtual_address,
                                  main->file.imageBase + it.virtual_address +
                                      it.virtual_size,
                                  MemoryAccessMode::SYMBOLIC);
    } else {
      // printvalue2(main->file.imageBase + it.virtual_address);
      // printvalue2(main->file.imageBase + it.virtual_address +
      // it.virtual_size); printvalue2("concrete");
      main->memoryPolicy.addRange(main->file.imageBase + it.virtual_address,
                                  main->file.imageBase + it.virtual_address +
                                      it.virtual_size,
                                  MemoryAccessMode::CONCRETE);
    }
  }
  main->memoryPolicy.addRange(STACKP_VALUE - 0x1000, STACKP_VALUE + 0x1000,
                              MemoryAccessMode::CONCRETE);
  /*   auto addr = 5369843712;
    main->memoryPolicy.addRange(addr + 2, addr + 0x4,
    MemoryAccessMode::SYMBOLIC);

    main->memoryPolicy.addRange(addr, addr + 0x1, MemoryAccessMode::CONCRETE);
  */
  main->blockInfo = BBInfo(runtime_address, main->bb);
  main->unvisitedBlocks.push_back(main->blockInfo);

  // main->InitRegisters(function, runtime_address);

  x86FileReader file(fileBase);
  auto dosHeader = (win::dos_header_t*)fileBase;
  if (*(unsigned short*)fileBase != 0x5a4d) {
    UNREACHABLE("Only PE files are supported");
  }

  // auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
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

  asm_to_zydis_to_lift(main, fileData);

  ms = timer::getTimer();

  std::cout << "\nlifting complete, " << std::dec << ms
            << " milliseconds has past" << std::endl;

  main->writeFunctionToFile("output_no_opts.ll");

  std::cout << "\nwriting complete, " << std::dec << ms
            << " milliseconds has past" << std::endl;

  // final_optpass(main->fnc, main->fnc->getArg(main->fnc->arg_size()),
  //               fileData.data(), main->memoryPolicy);
  main->run_opts();
  main->writeFunctionToFile("output.ll");
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
