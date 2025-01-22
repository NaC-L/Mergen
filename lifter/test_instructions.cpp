
#include "lifterClass.h"
#include "tester.hpp"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Disassembler.h>
#include <Zydis/Register.h>
#include <llvm/IR/Constants.h>

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

  auto tester = Tester(main, true);
  std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
  tester.setRegister(ZYDIS_REGISTER_RAX, 5);
  tester.setRegister(ZYDIS_REGISTER_RCX, 5);
  tester.disassembleBytesAndLift(bytes);
  auto a = tester.getRegister(ZYDIS_REGISTER_RAX);
  tester.getRegister(ZYDIS_REGISTER_RCX);

  return tester.isRegisterEqualTo(ZYDIS_REGISTER_RAX, 10);
}
