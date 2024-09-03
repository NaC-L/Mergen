

#include "FunctionSignatures.h"
#include "GEPTracker.h"
#include "OperandUtils.h"
#include "PathSolver.h"
#include "includes.h"
#include "lifterClass.h"
#include "nt/nt_headers.hpp"
#include "utils.h"
#include <fstream>

vector<lifterClass*> lifters;
uint64_t original_address = 0;
unsigned int pathNo = 0;
// consider having this function in a class, later we can use multi-threading to
// explore different paths
void asm_to_zydis_to_lift(ZyanU8* data) {

  while (lifters.size() > 0) {
    lifterClass* lifter = lifters.back();

    uint64_t offset = FileHelper::address_to_mapped_address(
        lifter->blockInfo.runtime_address);
    debugging::doIfDebug([&]() {
      cout << "runtime_addr: " << lifter->blockInfo.runtime_address
           << " offset:" << offset << " byte there: 0x" << (int)*(data + offset)
           << endl;
      cout << "offset: " << offset << " file_base?: " << original_address
           << " runtime: " << lifter->blockInfo.runtime_address << endl;
    });

    lifter->builder.SetInsertPoint(lifter->blockInfo.block);

    BinaryOperations::initBases(data, data);

    lifter->run = 1;

    for (; lifter->run && !lifter->finished &&
           lifter->blockInfo.runtime_address > 0;) {
      if (BinaryOperations::isWrittenTo(lifter->blockInfo.runtime_address)) {
        printvalueforce2(lifter->blockInfo.runtime_address);
        outs() << "SelfModifyingCode!\n";
        outs().flush();
      }

      ZydisDecoder decoder;
      ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                       ZYDIS_STACK_WIDTH_64);

      ZydisDecoderDecodeFull(&decoder, data + offset, 15,
                             &(lifter->instruction), lifter->operands);

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

        cout << hex << counter << ":" << buffer << "\n";
        cout << "runtime: " << runtime_address << endl;
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
        continue;
      }

      offset += lifter->instruction.length;
    }
  }
}

void InitFunction_and_LiftInstructions(ZyanU64 runtime_address,
                                       unsigned char* fileBase) {

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

  string function_name = "main";
  auto function =
      llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                             function_name.c_str(), lifting_module);
  string block_name = "entry";
  auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);
  llvm::IRBuilder<> builder = llvm::IRBuilder<>(bb);

  // auto RegisterList = InitRegisters(builder, function, runtime_address);

  lifterClass* main = new lifterClass(builder);
  main->InitRegisters(function, runtime_address);
  main->blockInfo = BBInfo(runtime_address, bb);

  main->fnc = function;
  main->initDomTree(*function);
  auto dosHeader = (win::dos_header_t*)fileBase;
  auto ntHeaders = (win::nt_headers_x64_t*)(fileBase + dosHeader->e_lfanew);
  auto ADDRESS = ntHeaders->optional_header.image_base;
  auto imageSize = ntHeaders->optional_header.size_image;
  auto stackSize = ntHeaders->optional_header.size_stack_reserve;
  uint64_t RVA = static_cast<uint64_t>(runtime_address - ADDRESS);
  uint64_t fileOffset = FileHelper::RvaToFileOffset(ntHeaders, RVA);
  uint8_t* dataAtAddress = fileBase + fileOffset;
  cout << hex << "0x" << (int)*dataAtAddress << endl;
  original_address = ADDRESS;
  cout << "address: " << ADDRESS << " imageSize: " << imageSize
       << " filebase: " << (uint64_t)fileBase << " fOffset: " << fileOffset
       << " RVA: " << RVA << endl;

  main->markMemPaged(STACKP_VALUE - stackSize, STACKP_VALUE + stackSize);
  main->markMemPaged(ADDRESS, ADDRESS + imageSize);

  // blockAddresses->push_back(make_tuple(runtime_address, bb, RegisterList));
  lifters.push_back(main);

  asm_to_zydis_to_lift(fileBase);

  long long ms = timer::getTimer();

  cout << "\nlifting complete, " << dec << ms << " milliseconds has past"
       << endl;

  final_optpass(function);
  string Filename = "output.ll";
  error_code EC;
  llvm::raw_fd_ostream OS(Filename, EC);

  if (EC) {
    llvm::errs() << "Could not open file: " << EC.message();
    return;
  }

  lifting_module.print(OS, nullptr);

  return;
}

int main(int argc, char* argv[]) {
  vector<string> args(argv, argv + argc);
  argparser::parseArguments(args);
  timer::startTimer();
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

  ifs.seekg(0, ios::end);
  vector<uint8_t> fileData(ifs.tellg());
  ifs.seekg(0, ios::beg);

  if (!ifs.read((char*)fileData.data(), fileData.size())) {
    cout << "Failed to read the file." << endl;
    return 1;
  }
  ifs.close();

  auto fileBase = fileData.data();

  FileHelper::setFileBase(fileBase);

  funcsignatures::search_signatures(fileData);
  funcsignatures::createOffsetMap();
  for (const auto& [key, value] : funcsignatures::siglookup) {
    value.display();
  }
  long long ms = timer::getTimer();
  cout << "\n" << dec << ms << " milliseconds has past" << endl;

  InitFunction_and_LiftInstructions(startAddr, fileBase);
  long long milliseconds = timer::stopTimer();
  cout << "\n" << dec << milliseconds << " milliseconds has past" << endl;
  cout << "Lifted and optimized " << debugging::increaseInstCounter() - 1
       << " total insts";
}
