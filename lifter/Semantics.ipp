#include "CommonDisassembler.hpp"
#include "FunctionSignatures.hpp"
#include "OperandUtils.ipp"
#include "PathSolver.ipp"
#include "fileReader.hpp"
#include "includes.h"
#include "lifterClass.hpp"
#include "utils.h"
#include <immintrin.h>
#include <iostream>
#include <llvm/IR/Constant.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/VersionTuple.h>
#include <magic_enum/magic_enum.hpp>

// #include <popcntintrin.h>

using namespace llvm;


// File-scoped naming counters for debug block names
int ret_count = 0;
int jmpcount = 0;
int branchnumber = 0;

// Semantic handler sub-files
#include "Semantics_Helpers.ipp"
#include "Semantics_Misc.ipp"
#include "Semantics_ControlFlow.ipp"
#include "Semantics_Arithmetic.ipp"
#include "Semantics_Bitwise.ipp"

// Dispatch machinery

#include "pp_macros.hpp"

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::liftInstructionSemantics() {

  switch (instruction.mnemonic) {

#define OPCODE_CASE(fn, mnemonic)                                              \
  case Mnemonic::mnemonic:                                                     \
    lift_##fn();                                                               \
    break;

#define OPCODE(fn, ...) __VA_OPT__(PP_FOREACH(OPCODE_CASE, fn, __VA_ARGS__))

#include "x86_64_opcodes.x"
#undef OPCODE
#undef OPCODE_CASE
  case Mnemonic::UD2: {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("exception", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }
  case Mnemonic::FXRSTOR:
  case Mnemonic::FXSAVE:
  case Mnemonic::PAUSE:
  case Mnemonic::NOP: {
    break;
  }
  case Mnemonic::Invalid: {

    printvalueforce2(this->counter);
    std::cout << "invalid: " << magic_enum::enum_name(instruction.mnemonic)
              << " runtime: " << std::hex << current_address << std::endl;
    /*
        std::string Filename = "output_notimplemented.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
        */
    // UNREACHABLE("Instruction not implemented");
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("invalid", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    break;
  }
  default: {

    printvalueforce2(this->counter);
    std::cout << "not implemented: "
              << magic_enum::enum_name(instruction.mnemonic)
              << " runtime: " << std::hex << current_address << std::endl;
    /*
        std::string Filename = "output_notimplemented.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
        */
    // UNREACHABLE("Instruction not implemented");
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    break;
  }
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::liftInstruction() {

  // in future this function could be staticly dispatched for custom logic?

  LLVMContext& context = builder->getContext();
  // RIP gets updated before execution of the instruction->
  /*
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    current_address);
  SetRegisterValueWrapper(Register::RIP, val);
  */
  // auto rsp = GetRegisterValue(Register::RSP);
  // printvalue(rsp);
  printvalue2(current_address);

  auto funcInfo = signatures.getFunctionInfo(current_address);

  if (funcInfo) {
    callFunctionIR(funcInfo->name.c_str(), funcInfo);
    outs() << "calling: " << funcInfo->name.c_str() << "\n";
    outs().flush();
    auto next_jump = popStack(file.getMode() == arch_mode::X64 ? 8 : 4);

    // get [rsp], jump there
    if (!isa<ConstantInt>(next_jump)) {
      UNREACHABLE("next_jump is not a ConstantInt.");
      return;
    }
    auto RIP_value = cast<ConstantInt>(next_jump);
    auto jump_address = RIP_value->getZExtValue();

    auto bb = getOrCreateBB(jump_address, "bb_call");
    builder->CreateBr(bb);

    blockInfo = BBInfo(jump_address, bb);
    run = 0;
    return;
  }

  // if really an import, jump_address + imagebase should return a std::string
  // (?)
  uint64_t jump_address = current_address;
  uint64_t temp;
  bool isReadable = file.readMemory(jump_address, 1, temp);
  // bool isImport = file.isImport(jump_address); check if rwx?

  // this ~~would~~ SHOULD catch missed function calls, probably take care of
  // this in solvePath?

  if (!isReadable &&
      cast<ConstantInt>(GetRegisterValue(Register::RSP))->getValue() !=
          STACKP_VALUE) {
    printvalueforce2(jump_address);

    // TODO: ideally remove this part
    auto bb = getOrCreateBB(jump_address, "bb_indirectly_called");
    // actually call the function first

    auto functionName = file.getName(jump_address);
    outs() << "calling : " << functionName
           << " addr: " << (uint64_t)jump_address;
    outs().flush();

    callFunctionIR(functionName, nullptr);

    auto next_jump = popStack(file.getMode() == arch_mode::X64 ? 8 : 4);

    // get [rsp], jump there
    auto RIP_value = cast<ConstantInt>(next_jump);
    jump_address = RIP_value->getZExtValue();

    builder->CreateBr(bb);

    blockInfo = BBInfo(jump_address, bb);
    run = 0;
    return;
  }

  /*
    if (!isReadable && !isImport) {
      // done something wrong;
      std::string Filename = "output_external.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);

      outs().flush();
      // UNREACHABLE("Trying to execute invalid external function");
    }
   */
  // do something for prefixes like rep here
  liftInstructionSemantics();
}