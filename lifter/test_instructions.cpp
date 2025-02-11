
#include "lifterClass.h"
#include "tester.hpp"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Disassembler.h>
#include <Zydis/Register.h>
#include <llvm/IR/Constants.h>

// & all the tests, if test fail, it should return 0

// make this so tests can be added seperately

bool test1(Tester* tester) {

  std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
  tester->setRegister(ZYDIS_REGISTER_RAX, 5);
  tester->setRegister(ZYDIS_REGISTER_RCX, 5);
  tester->disassembleBytesAndLift(bytes);

  auto res1 = tester->isRegisterEqualTo(ZYDIS_REGISTER_RAX, 10);
  return res1;
}

bool test2(Tester* tester) {

  std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
  tester->setRegister(ZYDIS_REGISTER_RAX, 10);
  tester->setRegister(ZYDIS_REGISTER_RCX, 10);
  tester->disassembleBytesAndLift(bytes);

  auto res1 = tester->isRegisterEqualTo(ZYDIS_REGISTER_RAX, 20);
  return res1;
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

  llvm::IRBuilder<> builder = llvm::IRBuilder<>(bb);

  lifterClass* main = new lifterClass(builder, 0x133700);

  // we will need a resetter, though im not sure if we need to only reset
  // registers, flags and mem or llvm context?

  auto tester = Tester(main, true);
  tester.addTest(test1, "test");
  tester.addTest(test2, "test2");
  TestCase tc = {.name = "testcase",
                 .instruction_bytes = {0x90},
                 .initial_registers = {{ZYDIS_REGISTER_RAX, 1}},
                 .initial_flags = {{FLAG_CF, FlagState::SET}},

                 .expected_registers = {{ZYDIS_REGISTER_RAX, 1}},
                 .expected_flags = {{FLAG_CF, FlagState::SET}}};
  tester.execute_test_case(tc);
  tester.addTest(tc);
  return tester.runAllTests();
}
