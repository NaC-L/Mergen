
#include "FunctionSignatures.h"
#include "GEPTracker.h"
#include "PathSolver.h"
#include "includes.h"
#include "lifterClass.h"
#include "nt/nt_headers.hpp"
#include "utils.h"
#include <fstream>
#include <iostream>
#include <llvm/IR/IRBuilderFolder.h>
#include <llvm/Support/NativeFormatting.h>

vector<lifterClass*> lifters;
uint64_t original_address = 0;
unsigned int pathNo = 0;
// consider having this function in a class, later we can use multi-threading to
// explore different paths
unsigned int breaking = 0;
arch_mode is64Bit;

void asm_to_zydis_to_lift(ZyanU8* data) {
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder,
                   is64Bit ? ZYDIS_MACHINE_MODE_LONG_64
                           : ZYDIS_MACHINE_MODE_LEGACY_32,
                   is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

  BinaryOperations::initBases(data, is64Bit); // sigh ?
  while (lifters.size() > 0) {
    lifterClass* lifter = lifters.back();

    uint64_t offset = BinaryOperations::address_to_mapped_address(
        lifter->blockInfo.runtime_address);
    debugging::doIfDebug([&]() {
      const auto printv =
          "runtime_addr: " + to_string(lifter->blockInfo.runtime_address) +
          " offset:" + to_string(offset) + " byte there: 0x" +
          to_string((int)*(data + offset)) + "\n" +
          "offset: " + to_string(offset) +
          " file_base: " + to_string(original_address) +
          " runtime: " + to_string(lifter->blockInfo.runtime_address) + "\n";
      printvalue2(printv);
    });

    lifter->builder.SetInsertPoint(lifter->blockInfo.block);

    lifter->run = 1;

    while ((lifter->run && !lifter->finished)) {

      if (BinaryOperations::isWrittenTo(lifter->blockInfo.runtime_address)) {
        printvalueforce2(lifter->blockInfo.runtime_address);
        UNREACHABLE("Found Self Modifying Code! we dont support it");
      }

      ZydisDecoderDecodeFull(&decoder, data + offset, 15,
                             &(lifter->instruction), lifter->operands);

      ++(lifter->counter);
      auto counter = debugging::increaseInstCounter() - 1;

      debugging::doIfDebug([&]() {
        ZydisFormatter formatter;

        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        char buffer[256];
        ZyanU64 runtime_address = 0;
        ZydisFormatterFormatInstruction(
            &formatter, &(lifter->instruction), lifter->operands,
            lifter->instruction.operand_count_visible, &buffer[0],
            sizeof(buffer), runtime_address, ZYAN_NULL);
        const auto ct = (format_hex_no_prefix(lifter->counter, 0));
        printvalue2(ct);
        const auto inst = buffer;
        printvalue2(inst);
        const auto runtime = lifter->blockInfo.runtime_address;
        printvalue2(runtime);
      });

      lifter->blockInfo.runtime_address += lifter->instruction.length;
      lifter->liftInstruction();
      if (lifter->finished) {

        lifter->run = 0;
        lifters.pop_back();

        debugging::doIfDebug([&]() {
          std::string Filename = "output_path_" + to_string(++pathNo) + ".ll";
          std::error_code EC;
          raw_fd_ostream OS(Filename, EC);
          lifter->fnc->getParent()->print(OS, nullptr);
        });
        outs() << "next lifter instance\n";

        delete lifter;
        continue;
      }

      offset += lifter->instruction.length;
    }
  }
}

void InitFunction_and_LiftInstructions(const ZyanU64 runtime_address,
                                       std::vector<uint8_t> fileData) {

  auto fileBase = fileData.data();
  LLVMContext context;
  string mod_name = "my_lifting_module";
  llvm::Module lifting_module = llvm::Module(mod_name.c_str(), context);

  vector<llvm::Type*> argTypes;
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

  const string function_name = "main";
  auto function =
      llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                             function_name.c_str(), lifting_module);
  const string block_name = "entry";
  auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);
  llvm::IRBuilder<> builder = llvm::IRBuilder<>(bb);

  // auto RegisterList = InitRegisters(builder, function, runtime_address);

  lifterClass* main = new lifterClass(builder);
  main->InitRegisters(function, runtime_address);
  main->blockInfo = BBInfo(runtime_address, bb);

  main->fnc = function;
  main->initDomTree(*function);
  auto dosHeader = (win::dos_header_t*)fileBase;
  if (*(unsigned short*)fileBase != 0x5a4d) {
    UNREACHABLE("Only PE files are supported");
  }

  auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
  auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

  auto ntHeaders = (win::nt_headers_t<true>*)(fileBase + dosHeader->e_lfanew);
  auto PEmagic = ntHeaders->optional_header.magic;

  is64Bit = (arch_mode)(PEmagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

  auto processHeaders = [fileBase, runtime_address,
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
    const uint64_t fileOffset =
        BinaryOperations::RvaToFileOffset(ntHeadersBase, RVA);
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
    return address;
  };

  original_address = processHeaders(fileBase + dosHeader->e_lfanew);

  funcsignatures::search_signatures(fileData);
  funcsignatures::createOffsetMap(); // ?
  for (const auto& [key, value] : funcsignatures::siglookup) {
    value.display();
  }
  auto ms = timer::getTimer();
  std::cout << "\n" << std::dec << ms << " milliseconds has past" << std::endl;

  // blockAddresses->push_back(make_tuple(runtime_address, bb,
  // RegisterList));
  lifters.push_back(main);

  asm_to_zydis_to_lift(fileBase);

  ms = timer::getTimer();

  cout << "\nlifting complete, " << dec << ms << " milliseconds has past"
       << endl;
  const string Filename_noopt = "output_no_opts.ll";
  error_code EC_noopt;
  llvm::raw_fd_ostream OS_noopt(Filename_noopt, EC_noopt);

  lifting_module.print(OS_noopt, nullptr);

  cout << "\nwriting complete, " << dec << ms << " milliseconds has past"
       << endl;
  final_optpass(function);
  const string Filename = "output.ll";
  error_code EC;
  llvm::raw_fd_ostream OS(Filename, EC);

  lifting_module.print(OS, nullptr);

  return;
}

int testInit() {
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

  lifterClass* main = new lifterClass(builder, 0x133700);
  // main->InitRegisters(function, );
  // main->blockInfo = BBInfo(0x133700, bb);

  auto tester = Tester(main, true);
  std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
  tester.setRegister(ZYDIS_REGISTER_RAX, 5);
  tester.setRegister(ZYDIS_REGISTER_RCX, 5);
  tester.disassembleBytesAndLift(bytes);
  auto a = tester.getRegister(ZYDIS_REGISTER_RAX);
  tester.getRegister(ZYDIS_REGISTER_RCX);

  if (auto a_c = dyn_cast<ConstantInt>(a)) {
    return !(a_c->equalsInt(10));
  }
  return 1;
}

// #define TEST

int main(int argc, char* argv[]) {
  vector<string> args(argv, argv + argc);
  argparser::parseArguments(args);
  timer::startTimer();

#ifdef MERGEN_TEST
  if (1 == 1)
    return testInit();
#endif

  // use parser
  if (args.size() < 3) {
    cerr << "Usage: " << args[0] << " <filename> <startAddr>" << endl;
    return 1;
  }

  // debugging::enableDebug();

  const char* filename = args[1].c_str();
  uint64_t startAddr = stoull(args[2], nullptr, 0);

  ifstream ifs(filename, ios::binary);
  if (!ifs.is_open()) {
    cout << "Failed to open the file." << endl;
    return 1;
  }

  ifs.seekg(0, std::ios::end);
  std::vector<uint8_t> fileData(ifs.tellg());
  ifs.seekg(0, std::ios::beg);

  if (!ifs.read((char*)fileData.data(), fileData.size())) {
    cout << "Failed to read the file." << endl;
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
