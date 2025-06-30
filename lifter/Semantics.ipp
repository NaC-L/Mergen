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

MERGEN_LIFTER_DEFINITION_TEMPLATES(FunctionType*)::parseArgsType(
    funcsignatures<Register>::functioninfo* funcInfo, LLVMContext& context) {
  if (!funcInfo) {
    FunctionType* externFuncType = FunctionType::get(
        Type::getInt64Ty(context),
        {llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context),
         llvm::Type::getInt64Ty(context), llvm::Type::getInt64Ty(context)},
        false);

    return externFuncType;
  }
  std::vector<llvm::Type*> argTypes;
  for (const auto& arg : funcInfo->args) {
    llvm::Type* type = nullptr;
    type = llvm::Type::getIntNTy(context, 8 << (arg.argtype.size - 1));

    if (arg.argtype.isPtr) {
      type = type->getPointerTo();
    }
    argTypes.push_back(type);
  }

  return llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes,
                                 false);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(std::vector<Value*>)::parseArgs(
    funcsignatures<Register>::functioninfo* funcInfo) {
  auto& context = builder->getContext();

  auto RspRegister = GetRegisterValue(Register::RSP);
  if (!funcInfo)
    return {createZExtFolder(GetRegisterValue(Register::RAX),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RCX),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RDX),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RBX),
                             Type::getInt64Ty(context)),
            RspRegister,
            createZExtFolder(GetRegisterValue(Register::RBP),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RSI),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RDI),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::RDI),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R8),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R9),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R10),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R11),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R12),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R13),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R14),
                             Type::getInt64Ty(context)),
            createZExtFolder(GetRegisterValue(Register::R15),
                             Type::getInt64Ty(context)),
            memoryAlloc};

  std::vector<Value*> args;
  for (const auto& arg : funcInfo->args) {
    Value* argValue = GetRegisterValue(arg.reg);
    argValue = createZExtOrTruncFolder(
        argValue, Type::getIntNTy(context, 8 << (arg.argtype.size - 1)));
    if (arg.argtype.isPtr)
      argValue = getPointer(argValue);
    //  now convert to pointer if its a pointer
    args.push_back(argValue);
  }
  return args;
}

// probably move this stuff somewhere else
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::callFunctionIR(
    const std::string& functionName,
    funcsignatures<Register>::functioninfo* funcInfo) {
  auto& context = builder->getContext();

  if (!funcInfo) {
    // try to get funcinfo from name
    funcInfo = signatures.getFunctionInfo(functionName);
  }
  FunctionType* externFuncType = parseArgsType(funcInfo, context);
  auto M = builder->GetInsertBlock()->getParent()->getParent();

  // what about ordinals???????
  Function* externFunc = cast<Function>(
      M->getOrInsertFunction(functionName, externFuncType).getCallee());
  // fix calling
  std::vector<Value*> args = parseArgs(funcInfo);
  auto callresult = builder->CreateCall(externFunc, args);

  SetRegisterValue(Register::RAX,
                   callresult); // rax = externalfunc()
  /*
  SetRegisterValueWrapper(Register::RAX,
                   builder->getInt64(1337)); // rax = externalfunc()
  */
  // check if the function is exit or something similar to that
  return callresult;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagAdc(
    Value* Lvalue, Value* Rvalue, Value* cf, Value* add) {
  auto cfc = createZExtOrTruncFolder(cf, add->getType(), "ofadc1");
  auto ofAdd = createAddFolder(add, cfc, "ofadc2");
  auto xor0 = createXorFolder(Lvalue, ofAdd, "ofadc3");
  auto xor1 = createXorFolder(Rvalue, ofAdd, "ofadc4");
  auto ofAnd = createAndFolder(xor0, xor1, "ofadc5");
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofadc6");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagAdd(
    Value* Lvalue, Value* Rvalue, Value* add) {
  auto xor0 = createXorFolder(Lvalue, add, "ofadd");
  auto xor1 = createXorFolder(Rvalue, add, "ofadd1");
  auto ofAnd = createAndFolder(xor0, xor1, "ofadd2");
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofadd3");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagSub(
    Value* Lvalue, Value* Rvalue, Value* sub) {
  auto xor0 = createXorFolder(Lvalue, Rvalue, "ofsub");
  auto xor1 = createXorFolder(Lvalue, sub, "ofsub1");
  auto ofAnd = createAndFolder(xor0, xor1, "ofsub2");
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofsub3");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagSbb(
    Value* Lvalue, Value* Rvalue, Value* cf, Value* sub) {

  auto bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto signBit = builder->getIntN(bitWidth, bitWidth - 1);

  auto lhsSign = createLShrFolder(Lvalue, signBit);
  auto rhsSign = createLShrFolder(Rvalue, signBit);
  auto resultSign = createLShrFolder(sub, signBit);

  auto result_idk = createXorFolder(lhsSign, rhsSign);
  auto result_idk2 = createXorFolder(lhsSign, resultSign);
  auto result_idk3 = createAddFolder(result_idk, result_idk2);

  return createICMPFolder(CmpInst::ICMP_EQ, result_idk3,
                          ConstantInt::get(result_idk3->getType(), 2),
                          "ofsbb5");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeAuxFlag(Value* Lvalue,
                                                           Value* Rvalue,
                                                           Value* result) {
  auto auxc = ConstantInt::get(result->getType(), 0x10);
  auto aux1 = createXorFolder(result, createXorFolder(Lvalue, Rvalue));
  auto aux2 = createAndFolder(auxc, aux1);
  auto af = createICMPFolder(CmpInst::ICMP_EQ, aux2, auxc);
  return af;
}

/*
https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits

Compute parity of a byte using 64-bit multiply and modulus division
unsigned char b;  // byte value to compute the parity of
bool parity =
  (((b * 0x0101010101010101ULL) & 0x8040201008040201ULL) % 0x1FF) & 1;
The method above takes around 4 operations, but only works on bytes.
*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeParityFlag(Value* value) {
  LLVMContext& context = value->getContext();

  Value* lsb = createZExtFolder(
      createAndFolder(value, ConstantInt::get(value->getType(), 0xFF), "lsb"),
      Type::getInt64Ty(context));

  // s or u rem?
  Value* parity = createAndFolder(

      createURemFolder(
          createAndFolder(

              createMulFolder(
                  lsb, ConstantInt::get(lsb->getType(), 0x0101010101010101),
                  "pf1"),
              ConstantInt::get(lsb->getType(), 0x8040201008040201ULL), "pf2"),
          ConstantInt::get(lsb->getType(), 0x1FF), "pf3"),
      ConstantInt::get(lsb->getType(), 1), "pf4");
  // parity
  parity = createICMPFolder(CmpInst::ICMP_EQ,
                            ConstantInt::get(lsb->getType(), 0), parity, "pf5");
  return parity; // Returns 1 if even parity, 0 if odd
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeZeroFlag(
    Value* value) { // x == 0 = zf
  return createICMPFolder(CmpInst::ICMP_EQ, value,
                          ConstantInt::get(value->getType(), 0), "zeroflag");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeSignFlag(
    Value* value) { // x < 0 = sf
  return createICMPFolder(CmpInst::ICMP_SLT, value,
                          ConstantInt::get(value->getType(), 0), "signflag");
}

// this function is used for jumps that are related to user, ex: vms using
// different handlers, jmptables, etc.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::branchHelper(
    Value* condition, const std::string& instname, int numbered, bool reverse) {
  // TODO:
  // save the current state of memory, registers etc.,
  // after execution is finished, return to latest state and continue
  // execution from the other branch

  auto block = builder->GetInsertBlock();
  block->setName(instname + std::to_string(numbered));
  auto function = block->getParent();

  auto true_jump_addr = instruction.immediate + current_address;

  Value* true_jump =
      ConstantInt::get(function->getReturnType(), true_jump_addr);

  auto false_jump_addr = current_address;
  Value* false_jump =
      ConstantInt::get(function->getReturnType(), false_jump_addr);
  Value* next_jump = nullptr;

  if (!reverse)
    next_jump = createSelectFolder(condition, true_jump, false_jump);
  else
    next_jump = createSelectFolder(condition, false_jump, true_jump);

  uint64_t destination = 0;
  solvePath(function, destination, next_jump);

  block->setName("previousjmp_block-" + std::to_string(destination) + "-");
  // cout << "pathInfo:" << pathInfo << " dest: " << destination  <<
  // "\n";
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bextr() {
  /*
  auto src2 = operands[2];
  auto src1 = operands[1];
  auto dst = operands[0];

  */
  auto info = GetIndexValue(2);
  auto source = GetIndexValue(1);

  auto len = createTruncFolder(
      createLShrFolder(info, ConstantInt::get(info->getType(), 8)),
      Type::getInt8Ty(fnc->getContext()));

  Value* bitmask = createAShrFolder(
      createShlFolder(ConstantInt::get(len->getType(), 1), len), len);
  auto source2 =
      createAndFolder(source, createZExtFolder(bitmask, source->getType()));

  SetIndexValue(0, source2);
  setFlag(FLAG_ZF, createICMPFolder(CmpInst::ICMP_EQ, source2,
                                    ConstantInt::get(source->getType(), 0)));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_movs_X() {

  LLVMContext& context = builder->getContext();

  // replace rep logic with memcopy

  // sign = (DF*(DF+1)) - 1
  // v = sign * byteSize

  int byteSizeValue = 0;
  switch (instruction.mnemonic) {
  case Mnemonic::MOVSB:
    byteSizeValue = 1;
    break;
  case Mnemonic::MOVSW:
    byteSizeValue = 2;
    break;
  case Mnemonic::MOVSD:
    byteSizeValue = 4;
    break;
  case Mnemonic::MOVSQ:
    byteSizeValue = 8;
    break;
  default:
    UNREACHABLE("unreachable case on lift_movs_X");
  }
  // [e/rsi] = [e/rdi]

  auto sourceReg = GetRegisterValue(Register::RSI);
  auto sourceVal = GetMemoryValue(sourceReg, byteSizeValue);

  auto destReg = GetRegisterValue(Register::RDI);

  Value* DF = getFlag(FLAG_DF);

  Value* Direction = createSelectFolder(
      DF,
      ConstantInt::get(
          Type::getIntNTy(context, sourceReg->getType()->getIntegerBitWidth()),
          -1 * byteSizeValue),
      ConstantInt::get(
          Type::getIntNTy(context, sourceReg->getType()->getIntegerBitWidth()),
          1 * byteSizeValue));

  printvalue2(magic_enum::enum_name(instruction.attributes));
  if (instruction.attributes == InstructionPrefix::Rep) {
    auto sizeReg = GetRegisterValue(Register::RCX);

    // currently it should memcpy properly even if direction is -, but it
    // should work with current impl, but fix it later
    auto size = createMulFolder(Direction, sizeReg);
    printvalue(sourceReg);
    printvalue(destReg);
    printvalue(size);
    createMemcpy(sourceReg, destReg, size);

    sourceReg = createAddFolder(sourceReg, Direction);
    destReg = createAddFolder(destReg, Direction);
    printvalue(sourceReg);
    printvalue(destReg);
    SetRegisterValue(Register::RSI, sourceReg);
    SetRegisterValue(Register::RDI, destReg);

    // also update sourceReg and destReg properly
    return;
  }

  SetMemoryValue(destReg, sourceVal);

  sourceReg = createAddFolder(sourceReg, Direction);
  destReg = createAddFolder(destReg, Direction);
  printvalue(sourceReg);
  printvalue(destReg);
  SetRegisterValue(Register::RDI, sourceReg);
  SetRegisterValue(Register::RSI, destReg);

  // this doesnt set flags, so if its rep/repz/repnz, we could do a trick with
  // memcpy
}
/*
void lifterClass<Mnemonic, Register, T3>::lift_movaps() {
  auto dest = operands[0];
  auto src = operands[1];

  auto Rvalue =
      GetIndexValue(src, src.size, std::to_string(current_address));
  SetIndexValue(dest, Rvalue, std::to_string(current_address));
}
*/
/*
void lifterClass<Mnemonic, Register, T3>::lift_xorps() {

  auto dest = operands[0]; // 128
  auto src = operands[1];  // 128

  // only legal:
  // rr
  // mr
  // rm

  auto Lvalue =
      GetIndexValueFP(dest, std::to_string(current_address));
  auto Rvalue =
      GetIndexValueFP(src, std::to_string(current_address));
  printvalue(Rvalue.v1);
  printvalue(Rvalue.v2);
  auto dest1 = createXorFolder(Rvalue.v1, Lvalue.v1);
  auto desRegister = createXorFolder(Rvalue.v2, Lvalue.v2);
  Rvalue.v1 = dest1;
  Rvalue.v2 = desRegister;
  SetIndexValueFP(dest, Rvalue, std::to_string(current_address));
}

void lifterClass<Mnemonic, Register, T3>::lift_movdqa() {
  auto dest = operands[0]; // 128
  auto src = operands[1];  // 128

  // only legal:
  // rr
  // mr
  // rm

  auto Rvalue =
      GetIndexValueFP(src, std::to_string(current_address));
  printvalue(Rvalue.v1);
  printvalue(Rvalue.v2);
  SetIndexValueFP(dest, Rvalue, std::to_string(current_address));
}

void lifterClass<Mnemonic, Register, T3>::lift_pand() {
  auto dest = operands[0]; // 128
  auto src = operands[1];  // 128

  // only legal:
  // rr
  // mr
  // rm

  auto Rvalue =
      GetIndexValueFP(src, std::to_string(current_address));
  auto Lvalue =
      GetIndexValueFP(dest, std::to_string(current_address));
  printvalue(Rvalue.v1);
  printvalue(Rvalue.v2);
  printvalue(Lvalue.v1);
  printvalue(Lvalue.v2);
  Rvalue.v1 = createAndFolder(Rvalue.v1, Lvalue.v1);
  Rvalue.v2 = createAndFolder(Rvalue.v2, Lvalue.v2);
  SetIndexValueFP(dest, Rvalue, std::to_string(current_address));
}

void lifterClass<Mnemonic, Register, T3>::lift_por() {
  auto dest = operands[0]; // 128
  auto src = operands[1];  // 128

  // only legal:
  // rr
  // mr
  // rm

  auto Rvalue =
      GetIndexValueFP(src, std::to_string(current_address));
  auto Lvalue =
      GetIndexValueFP(dest, std::to_string(current_address));
  printvalue(Rvalue.v1);
  printvalue(Rvalue.v2);
  printvalue(Lvalue.v1);
  printvalue(Lvalue.v2);
  Rvalue.v1 = createOrFolder(Rvalue.v1, Lvalue.v1);
  Rvalue.v2 = createOrFolder(Rvalue.v2, Lvalue.v2);
  SetIndexValueFP(dest, Rvalue, std::to_string(current_address));
}
void lifterClass<Mnemonic, Register, T3>::lift_pxor() {
  auto dest = operands[0]; // 128
  auto src = operands[1];  // 128

  // only legal:
  // rr
  // mr
  // rm

  auto Rvalue =
      GetIndexValueFP(src, std::to_string(current_address));
  auto Lvalue =
      GetIndexValueFP(dest, std::to_string(current_address));
  printvalue(Rvalue.v1);
  printvalue(Rvalue.v2);
  printvalue(Lvalue.v1);
  printvalue(Lvalue.v2);
  Rvalue.v1 = createXorFolder(Rvalue.v1, Lvalue.v1);
  Rvalue.v2 = createXorFolder(Rvalue.v2, Lvalue.v2);
  SetIndexValueFP(dest, Rvalue, std::to_string(current_address));
}
*/

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_mov() {
  LLVMContext& context = builder->getContext();

  //  auto Rvalue2 =      GetIndexValue(src, src.size,
  //  std::to_string(current_address));
  auto Rvalue = GetIndexValue(1);

  printvalue(Rvalue);

  switch (instruction.mnemonic) {
  case Mnemonic::MOVSX: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVZX: {
    Rvalue = createZExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movzx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVSXD: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsxd-" + std::to_string(current_address) + "-");
    break;
  }
  default: {
    break;
  }
  }
  printvalue(Rvalue);

  switch (instruction.types[1]) {
  // case OperandType::Immediate64:
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])));
    break;
  }
  default:
    break;
  }

  printvalue(Rvalue);

  SetIndexValue(0, Rvalue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmovcc() {

  auto getCondition = [&] {
    switch (instruction.mnemonic) {

    case Mnemonic::CMOVZ: {
      return getFlag(FLAG_ZF);
    }

    case Mnemonic::CMOVNZ: {
      return createNotFolder(getFlag(FLAG_ZF));
    }

    case Mnemonic::CMOVB: {
      return getFlag(FLAG_CF);
    }
    case Mnemonic::CMOVNB: {
      return createNotFolder(getFlag(FLAG_CF));
    }

    case Mnemonic::CMOVBE: {
      return createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNBE: {
      return createNotFolder(
          createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVL: {
      return createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF));
    }
    case Mnemonic::CMOVNL: {
      // equal
      return createNotFolder(
          createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)));
    }

    case Mnemonic::CMOVLE: {
      return createOrFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)),
                            getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNLE: {
      return createAndFolder(
          createNotFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF))),
          createNotFolder(getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVO: {
      return getFlag(FLAG_OF);
    }
    case Mnemonic::CMOVNO: {
      return createNotFolder(getFlag(FLAG_OF));
    }

    case Mnemonic::CMOVS: {
      return getFlag(FLAG_SF);
    }
    case Mnemonic::CMOVNS: {
      return createNotFolder(getFlag(FLAG_SF));
    }

    case Mnemonic::CMOVP: {
      return getFlag(FLAG_PF);
    }
    case Mnemonic::CMOVNP: {
      return createNotFolder(getFlag(FLAG_PF));
    }

    default: {
      return static_cast<Value*>(nullptr);
    }
    }
  };

  auto dest = GetIndexValue(0);

  auto src = GetIndexValue(1);

  auto result = createSelectFolder(getCondition(), src, dest);

  SetIndexValue(0, result);
}

// for now assume every call is fake
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_call() {
  LLVMContext& context = builder->getContext();

  // 0 = function
  // 1 = rip
  // 2 = register rsp
  // 3 = [rsp]
  /*
  auto src = operands[0];        // value that we are pushing
  auto rsp = operands[2];        // value that we are pushing
  auto rsp_memory = operands[3]; // value that we are pushing
  */
  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);

  auto result = createSubFolder(RspValue, val, "pushing_newrsp");

  uint64_t jump_address = current_address;

  std::string block_name = "jmp_call-" + std::to_string(jump_address) + "-";

  auto registerValue = GetIndexValue(0);
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16: // todo : pretty sure this 8 and 16 will cause
                                 // troubles later
  case OperandType::Immediate32:
  case OperandType::Immediate64: {

    // if (auto imm = dyn_cast<ConstantInt>(GetIndexValue(0))) {
    //   jump_address += imm->getSExtValue();
    //   break;
    // }
    // UNREACHABLE("wont reach");
    // break;
  }
  case OperandType::Memory8:
  case OperandType::Memory16: // todo : pretty sure this 8 and 16 will cause
                              // troubles later
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    registerValue =
        createAddFolder(registerValue, GetRegisterValue(Register::RIP));
    // auto registerValue = GetIndexValue(0);
    if (getControlFlow() == ControlFlow::Basic ||
        !isa<ConstantInt>(registerValue)) {

      std::cout << "did call";
      registerValue->print(outs());
      std::cout << "\n";
      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                          parseArgs(nullptr));

      break;
    }
    auto registerCValue = cast<ConstantInt>(registerValue);
    if (inlinePolicy.isOutline(registerCValue->getZExtValue())) {

      std::cout << "did call";
      registerValue->print(outs());
      std::cout << "\n";
      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                          parseArgs(nullptr));

      break;
    }
    jump_address = registerCValue->getZExtValue();
    break;
  }
  default:
    UNREACHABLE("unreachable in call");
    break;
  }

  // if inlining call
  // TODO:
  if (getControlFlow() == ControlFlow::Unflatten) {
    SetRegisterValue(Register::RSP, result);
    // // sub rsp 8 last,

    auto push_into_rsp = GetRegisterValue(Register::RIP);

    SetMemoryValue(getSPaddress(), push_into_rsp);
    // // sub rsp 8 last,

    auto bb = getOrCreateBB(jump_address, "bb_call");
    // if its trying to jump somewhere else than our binary, call it and
    // continue from [rsp]

    // // TODO: add some of this code to solvePath
    builder->CreateBr(bb);

    // printvalue2(jump_address);

    blockInfo = BBInfo(jump_address, bb);
    printvalue2("pushing block");
    addUnvisitedAddr(blockInfo);
    run = 0;
  }
}

int ret_count = 0;
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_ret() { // fix
  LLVMContext& context = builder->getContext();
  // [0] = rip
  // [1] = rsp
  // [2] = [rsp]

  // if its ret 0x10
  // then its
  // [0] = 0x10
  // [1] = rip
  // [2] = rsp
  // [3] = [rsp]

  auto rspvalue = GetRegisterValue(Register::RSP);

  // IMPORTANT, change logic
  auto realval = GetMemoryValue(getSPaddress(), 64); // todo : based on bitness

  auto block = builder->GetInsertBlock();
  auto function = block->getParent();
  // auto lastinst = builder->CreateRet(realval);

  printvalue(rspvalue);

  // remov
  debugging::doIfDebug([&]() {
    std::string Filename = "output_rets.ll";
    std::error_code EC;
    raw_fd_ostream OS(Filename, EC);
    function->getParent()->print(OS, nullptr);
  });

  uint64_t destination = 0;

  uint8_t rop_result = REAL_return;

  if (llvm::ConstantInt* constInt =
          llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
    int64_t rspval = constInt->getSExtValue();
    printvalue2(rspval);
    rop_result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
  }
  printvalue2(rop_result);
  if (rop_result == REAL_return) {
    // lastinst->eraseFromParent();
    block->setName("real_return-" + std::to_string(current_address) + "-");

    auto rax = GetRegisterValue(Register::RAX);
    rax = createZExtFolder(
        rax, builder->getIntNTy(file.getMode() == arch_mode::X64 ? 64 : 32));
    // put this in a function
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
    auto myStructType = StructType::create(context, argTypes, "returnStruct");

    auto myStruct = UndefValue::get(myStructType);
    // Use CreateInsertValue for structs
    // auto returnvalue = builder->CreateInsertValue(myStruct, rax, {0});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RCX), {1});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RDX), {2});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RBX), {3});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RSP), {4});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RBP), {5});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RSI), {6});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RDI), {7});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R8), {8});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R9), {9});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R10), {10});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R11), {11});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R12), {12});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R13), {13});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R14), {14});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R15), {15});
    builder->CreateRet(rax);
    Function* originalFunc_finalnopt = builder->GetInsertBlock()->getParent();

    run = 0;
    finished = 1;
    printvalue2(finished);
    return;
  }

  // lastinst->eraseFromParent();

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);
  auto rsp_result = createAddFolder(
      rspvalue, val, "ret-new-rsp-" + std::to_string(current_address) + "-");

  if (instruction.types[0] == OperandType::Immediate16) {

    rsp_result =
        createAddFolder(rsp_result, ConstantInt::get(rsp_result->getType(),
                                                     instruction.immediate));
  }

  SetRegisterValue(Register::RSP, rsp_result); // then add rsp 8

  solvePath(function, destination, realval);
}

int jmpcount = 0;
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jmp() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];
  auto Value = GetIndexValue(0);
  auto ripval = GetRegisterValue(Register::RIP);
  Value = createSExtFolder(Value, ripval->getType());
  // TODO:
  // if its an imm, sext
  // if its r/m then we probably need to zext
  // auto newRip = createAddFolder(
  //    Value, ripval, "jump-xd-" + std::to_string(current_address) + "-");
  jmpcount++;
  auto targetv = Value;
  auto trunc = createSExtOrTruncFolder(targetv, Type::getInt64Ty(context),
                                       "jmp-register");
  printvalue(ripval);
  printvalue(trunc);
  uint64_t destination = 0;
  auto function = builder->GetInsertBlock()->getParent();
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16: // todo: test 8 and 16
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    trunc = createAddFolder(trunc, ripval);
    printvalue(trunc);
  }
  default:
    break;
  }
  solvePath(function, destination, trunc);
  printvalue2(destination);
  // printvalue(newRip);
  // SetRegisterValueWrapper(Register::RIP, newRip);
}

int branchnumber = 0;
// jnz and jne
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnz() {

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  printvalue(zf);

  branchHelper(zf, "jnz", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_js() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "js");

  branchHelper(sf, "js", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jns() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jns");

  branchHelper(sf, "jns", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jz() {

  // if 0, then jmp, if not then not jump

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  branchHelper(zf, "jz", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jle", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jl");
  printvalue(sf);
  printvalue(of);
  auto condition = createXorFolder(sf, of, "jl_Condition");

  branchHelper(condition, "jl", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnl");

  printvalue(sf);
  printvalue(of);

  auto condition = createXorFolder(sf, of, "jl_condition");

  branchHelper(condition, "jnl", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jnle", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf) // auto dest = operands[0];

      // auto Value = GetIndexValue( dest, 64);
      // auto ripval = GetRegisterValue( Register::RIP);
      // auto newRip = createAddFolder( Value, ripval, "jbe");

      auto condition = createOrFolder(cf, zf, "jbe_Condition");

  branchHelper(condition, "jbe", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jb");

  auto condition = cf;
  branchHelper(condition, "jb", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnb");

  auto condition = cf;
  branchHelper(condition, "jnb", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf); // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jbe");

  auto condition = createOrFolder(cf, zf, "jnbe_Condition");

  branchHelper(condition, "jnbe", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jo() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jo");

  printvalue(of);
  branchHelper(of, "jo", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jno() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jno");

  branchHelper(of, "jno", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jp() {

  auto pf = getFlag(FLAG_PF);
  printvalue(pf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jp");

  branchHelper(pf, "jp", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnp() {

  auto pf = getFlag(FLAG_PF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnp");

  printvalue(pf);
  branchHelper(pf, "jnp", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_sbb() {
  /*
  auto dest = operands[0];
  auto src = operands[1];
*/
  Value* Lvalue = GetIndexValue(0);

  Value* Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  Value* cf = createZExtOrTruncFolder(getFlag(FLAG_CF), Rvalue->getType());

  Value* tmpResult = createSubFolder(Lvalue, Rvalue, "lhssubrhs");
  Value* result = createSubFolder(tmpResult, cf, "sbbTempResult");

  SetIndexValue(0, result);

  // 0, 0 (cf = 1), NEW CF = 1
  Value* newCF = createOrFolder(
      createICMPFolder(CmpInst::ICMP_ULT, Lvalue, Rvalue, "newCF"),
      createICMPFolder(CmpInst::ICMP_ULT, tmpResult, cf, "newCF2"));

  Value* sf = computeSignFlag(result);
  Value* zf = computeZeroFlag(result);
  Value* pf = computeParityFlag(result);
  Value* af = computeAuxFlag(Lvalue, Rvalue, result);

  auto of = computeOverflowFlagSbb(Lvalue, Rvalue, cf, result);

  setFlag(FLAG_CF, newCF);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, pf);
  setFlag(FLAG_AF, af);
  setFlag(FLAG_OF, of);

  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(tmpResult);
  printvalue(result);
  printvalue(sf);
  printvalue(of);
}

/*

(* RCL and RCR Instructions *)
SIZE := OperandSize;
CASE (determine count) OF
        SIZE := 8: tempCOUNT := (COUNT AND 1FH) MOD 9;
        SIZE := 16: tempCOUNT := (COUNT AND 1FH) MOD 17;
        SIZE := 32: tempCOUNT := COUNT AND 1FH;
        SIZE := 64: tempCOUNT := COUNT AND 3FH;
ESAC;
IF OperandSize = 64
        THEN COUNTMASK = 3FH;
        ELSE COUNTMASK = 1FH;
FI;
(* RCL Instruction Operation *)
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := MSB(DEST);
        DEST := (DEST ∗ 2) + CF;
        CF := tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
FI;
*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_rcl() {
  LLVMContext& context = builder->getContext();
  /*
  auto dest = operands[0];
  auto count = operands[1];
  */

  auto Lvalue = GetIndexValue(0);
  auto countValue = GetIndexValue(1);

  countValue = createZExtFolder(countValue, Lvalue->getType());

  auto carryFlag = getFlag(FLAG_CF);
  auto destsize = GetTypeSize(instruction.types[0]);
  // Create count mask based on operand size
  auto countmask =
      ConstantInt::get(countValue->getType(), destsize == 64 ? 0x3f : 0x1f);
  auto actualCount = createAndFolder(countValue, countmask, "maskCount");

  // Create constants
  auto bitWidthplusone = ConstantInt::get(Lvalue->getType(), destsize + 1);
  auto one = ConstantInt::get(Lvalue->getType(), 1);
  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  // Normalize count to be within valid range
  actualCount = createURemFolder(actualCount, bitWidthplusone);

  // Create a double-width value to handle CF rotation
  auto wideType = Type::getIntNTy(context, destsize * 2);
  auto wideLvalue = createZExtFolder(Lvalue, wideType);
  auto wideCF = createZExtFolder(carryFlag, wideType);

  // Position CF at bit position 0
  auto combinedValue = createOrFolder(
      createShlFolder(wideLvalue, ConstantInt::get(wideType, 1)), wideCF);

  // Perform rotation
  auto leftShifted =
      createShlFolder(combinedValue, createZExtFolder(actualCount, wideType));
  auto rightShifted = createLShrFolder(
      combinedValue,
      createSubFolder(createZExtFolder(bitWidthplusone, wideType),
                      createZExtFolder(actualCount, wideType)));
  auto rotated = createOrFolder(leftShifted, rightShifted);

  // Extract result and new CF
  auto result = createTruncFolder(
      createLShrFolder(rotated, ConstantInt::get(wideType, 1)),
      Lvalue->getType());

  auto newCF = createTruncFolder(rotated, Type::getInt1Ty(context));

  // Calculate OF (XOR of MSB and new CF) when count is 1
  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);
  auto msb = createZExtOrTruncFolder(createLShrFolder(result, MSBpos),
                                     Type::getInt1Ty(context));
  auto ofDefined = createZExtOrTruncFolder(createXorFolder(msb, newCF),
                                           Type::getInt1Ty(context));

  // OF is only valid when count is 1
  auto isCountOne = createICMPFolder(CmpInst::ICMP_EQ, actualCount, one);
  auto newOF = createSelectFolder(isCountOne, ofDefined, getFlag(FLAG_OF));

  // If count is 0, keep original value and flags
  auto isCountZero = createICMPFolder(CmpInst::ICMP_EQ, actualCount, zero);
  result = createSelectFolder(isCountZero, Lvalue, result);
  newCF = createSelectFolder(isCountZero, carryFlag, newCF);
  newOF = createSelectFolder(isCountZero, getFlag(FLAG_OF), newOF);

  // Set final results
  SetIndexValue(0, result);
  setFlag(FLAG_CF, newCF);
  setFlag(FLAG_OF, newOF);
}

/*
        (* RCL and RCR Instructions *)
SIZE := OperandSize;
CASE (determine count) OF
        SIZE := 8: tempCOUNT := (COUNT AND 1FH) MOD 9;
        SIZE := 16: tempCOUNT := (COUNT AND 1FH) MOD 17;
        SIZE := 32: tempCOUNT := COUNT AND 1FH;
        SIZE := 64: tempCOUNT := COUNT AND 3FH;
ESAC;
IF OperandSize = 64
        THEN COUNTMASK = 3FH;
        ELSE COUNTMASK = 1FH;
FI;
(* RCR Instruction Operation *)
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
FI;
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := LSB(SRC);
        DEST := (DEST / 2) + (CF * 2SIZE);
        CF := tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;

*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_rcr() {
  LLVMContext& context = builder->getContext();
  /*
  auto dest = operands[0];
  auto count = operands[1];
 */
  auto Lvalue = GetIndexValue(0);
  auto countValue = GetIndexValue(1);
  auto destsize = GetTypeSize(instruction.types[0]);
  countValue = createZExtFolder(countValue, Lvalue->getType());

  auto carryFlag = getFlag(FLAG_CF);

  // Create count mask based on operand size
  auto countmask =
      ConstantInt::get(countValue->getType(), destsize == 64 ? 0x3f : 0x1f);
  auto actualCount = createAndFolder(countValue, countmask, "maskCount");

  // Create constants
  auto bitWidthplusone = ConstantInt::get(Lvalue->getType(), destsize + 1);

  auto one = ConstantInt::get(Lvalue->getType(), 1);
  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  // Normalize count to be within valid range
  actualCount = createURemFolder(actualCount, bitWidthplusone);

  // Create a double-width value to handle CF rotation
  auto wideType = Type::getIntNTy(context, destsize * 2);
  auto wideLvalue = createZExtFolder(Lvalue, wideType);
  auto wideCF = createZExtFolder(carryFlag, wideType);

  // Position CF at the highest bit of the original value size
  auto shiftedCF =
      createShlFolder(wideCF, ConstantInt::get(wideType, destsize));
  auto combinedValue = createOrFolder(wideLvalue, shiftedCF);

  // Perform rotation
  auto rightShifted =
      createLShrFolder(combinedValue, createZExtFolder(actualCount, wideType));
  auto leftShifted = createShlFolder(
      combinedValue,
      createSubFolder(createZExtFolder(bitWidthplusone, wideType),
                      createZExtFolder(actualCount, wideType)));
  auto rotated = createOrFolder(rightShifted, leftShifted);

  // Extract result and new CF
  auto result = createTruncFolder(rotated, Lvalue->getType());
  auto newCF = createTruncFolder(
      createLShrFolder(rotated, ConstantInt::get(wideType, destsize)),
      Type::getInt1Ty(context));

  // Calculate OF (XOR of two most significant bits) when count is 1
  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);
  auto secondMSBpos = ConstantInt::get(Lvalue->getType(), destsize - 2);

  auto msb = createZExtOrTruncFolder(createLShrFolder(result, MSBpos),
                                     Type::getInt1Ty(context));
  auto secondMsb = createZExtOrTruncFolder(
      createLShrFolder(result, secondMSBpos), Type::getInt1Ty(context));
  auto ofDefined = createZExtOrTruncFolder(createXorFolder(msb, secondMsb),
                                           Type::getInt1Ty(context));

  // OF is only valid when count is 1
  auto isCountOne = createICMPFolder(CmpInst::ICMP_EQ, actualCount, one);
  auto newOF = createSelectFolder(isCountOne, ofDefined, getFlag(FLAG_OF));

  // If count is 0, keep original value and flags
  auto isCountZero = createICMPFolder(CmpInst::ICMP_EQ, actualCount, zero);
  result = createSelectFolder(isCountZero, Lvalue, result);
  printvalue(isCountZero);
  printvalue(carryFlag);
  newCF = createSelectFolder(isCountZero, carryFlag, newCF);
  newOF = createSelectFolder(isCountZero, getFlag(FLAG_OF), newOF);
  printvalue(Lvalue);
  printvalue(countValue);
  printvalue(actualCount);
  printvalue(carryFlag);
  printvalue(shiftedCF);
  printvalue(combinedValue);
  printvalue(rightShifted);
  printvalue(leftShifted);
  printvalue(rotated);
  printvalue(result);
  printvalue(newCF);
  // Set final results
  SetIndexValue(0, result);
  setFlag(FLAG_CF, newCF);
  setFlag(FLAG_OF, newOF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_not() {

  // auto dest = operands[0];

  auto Rvalue = GetIndexValue(0);
  Rvalue = createXorFolder(Rvalue, Constant::getAllOnesValue(Rvalue->getType()),
                           "realnot-" + std::to_string(current_address) + "-");
  SetIndexValue(0, Rvalue);

  printvalue(Rvalue);
  //  Flags Affected
  // None
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_neg() {

  // auto dest = operands[0];
  auto Rvalue = GetIndexValue(0);

  auto cf = createICMPFolder(CmpInst::ICMP_NE, Rvalue,
                             ConstantInt::get(Rvalue->getType(), 0), "cf");
  auto result = createSubFolder(
      builder->getIntN(Rvalue->getType()->getIntegerBitWidth(), 0), Rvalue,
      "neg");
  SetIndexValue(0, result);

  auto sf = computeSignFlag(result);
  auto zf = computeZeroFlag(result);
  Value* fifteen = ConstantInt::get(Rvalue->getType(), 0xf);
  auto af = createICMPFolder(CmpInst::ICMP_NE, createAndFolder(Rvalue, fifteen),
                             ConstantInt::get(Rvalue->getType(), 0), "af");
  auto isZero = createICMPFolder(
      CmpInst::ICMP_NE, Rvalue, ConstantInt::get(Rvalue->getType(), 0), "zero");

  printvalue(Rvalue) printvalue(result) printvalue(sf);
  // if of is not 0 and input and output is equal, of is set (input is just sign
  // bit)

  Value* of;

  of = createICMPFolder(CmpInst::ICMP_EQ, result, Rvalue);
  of = createSelectFolder(isZero, of, ConstantInt::get(of->getType(), 0));

  printvalue(of);
  // The CF flag set to 0 if the source operand is 0; otherwise it is set
  // to 1. The OF, SF, ZF, AF, and PF flags are set according to the
  // result.
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });
  setFlag(FLAG_OF, of);
  setFlag(FLAG_AF, af);
}

/*

IF 64-Bit Mode and using REX.W
        THEN
                countMASK := 3FH;
        ELSE
                countMASK := 1FH;
FI
tempCOUNT := (COUNT AND countMASK);
tempDEST := DEST;
WHILE (tempCOUNT ≠ 0)
DO
        IF instruction is SAL or SHL
                THEN
                CF := MSB(DEST);
        ELSE (* Instruction is SAR or SHR *)
                CF := LSB(DEST);
        FI;
        IF instruction is SAL or SHL
                THEN
                        DEST := DEST ∗ 2;
        ELSE
                IF instruction is SAR
                        THEN
                                DEST := DEST / 2; (* Signed divide, rounding
toward negative infinity *) ELSE (* Instruction is SHR *) DEST := DEST / 2 ;
(* Unsigned divide *) FI; FI; tempCOUNT := tempCOUNT – 1; OD;

(* Determine overflow for the various instructions *)
IF (COUNT and countMASK) = 1
        THEN
        IF instruction is SAL or SHL
                THEN
                OF := MSB(DEST) XOR CF;
        ELSE
        IF instruction is SAR
                THEN
                OF := 0;
        ELSE (* Instruction is SHR *)
                OF := MSB(tempDEST);
        FI;
FI;

ELSE IF (COUNT AND countMASK) = 0
        THEN
        All flags unchanged;
ELSE (* COUNT not 1 or 0 *)
OF := undefined;
FI;
FI;

*/
// maybe
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_sar() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0 + (instruction.mnemonic == Mnemonic::SARX)];
  // auto count = operands[1 + (instruction.mnemonic == Mnemonic::SARX)];
  auto dest = 0 + (instruction.mnemonic == Mnemonic::SARX);
  auto count = 1 + (instruction.mnemonic == Mnemonic::SARX);
  Value* Lvalue = GetIndexValue(dest);
  Value* countValue = GetIndexValue(count);
  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  unsigned maskC = bitWidth == 64 ? 0x3f : 0x1f;

  Value* clampedCount = createAndFolder(
      countValue, ConstantInt::get(countValue->getType(), maskC), "sarclamp");

  Value* zero = ConstantInt::get(clampedCount->getType(), 0);

  Value* maxShift = ConstantInt::get(clampedCount->getType(), bitWidth - 1);

  Value* isZeroed = createICMPFolder(CmpInst::ICMP_UGT, clampedCount, maxShift);

  Value* actual_clampedCount = clampedCount;

  // Shift by bitWidth - 1 if clampedCount exceeds bitWidth - 1
  clampedCount = createSelectFolder(isZeroed, maxShift, clampedCount);

  Value* result =
      createAShrFolder(Lvalue, clampedCount,
                       "sar-ashr-" + std::to_string(current_address) + "-");

  auto last_shift = createAShrFolder(
      Lvalue,
      createSubFolder(actual_clampedCount,
                      ConstantInt::get(clampedCount->getType(), 1)),
      "sarcf");

  auto signbitPos = bitWidth - 1;

  auto signBit =
      createAShrFolder(Lvalue, builder->getIntN(bitWidth, signbitPos), "sarcf");
  Value* cfValue = createTruncFolder(last_shift, builder->getInt1Ty());

  Value* isCountZero =
      createICMPFolder(CmpInst::ICMP_EQ, clampedCount,
                       ConstantInt::get(clampedCount->getType(), 0));

  Value* oldcf = getFlag(FLAG_CF);

  cfValue = createSelectFolder(isCountZero, oldcf, cfValue, "cfValue");
  // if isZeroed and the source is -, return the sign bit

  cfValue = createSelectFolder(
      isZeroed, createTruncFolder(signBit, cfValue->getType()), cfValue);

  // OF is cleared for SAR
  Value* of = ConstantInt::get(Type::getInt1Ty(context), 0);

  // Update flags only when count is not zero
  LazyValue isNotZero([this, clampedCount, zero]() {
    return createICMPFolder(CmpInst::ICMP_NE, clampedCount, zero);
  });
  LazyValue oldsf = getLazyFlag(FLAG_SF);
  LazyValue oldzf = getLazyFlag(FLAG_PF);
  LazyValue oldpf = getLazyFlag(FLAG_ZF);
  if (instruction.mnemonic != Mnemonic::SARX) {
    setFlag(FLAG_SF, [this, isNotZero, oldsf, result]() {
      return createSelectFolder(isNotZero.get(), computeSignFlag(result),
                                oldsf.get());
    });
    setFlag(FLAG_ZF, [this, isNotZero, oldzf, result]() {
      return createSelectFolder(isNotZero.get(), computeZeroFlag(result),
                                oldzf.get());
    });

    setFlag(FLAG_PF, [this, isNotZero, oldpf, result]() {
      return createSelectFolder(isNotZero.get(), computeParityFlag(result),
                                oldpf.get());
    });

    setFlag(FLAG_CF, cfValue);
    setFlag(FLAG_OF, of);
  }

  SetIndexValue(0, result);
}

// TODO fix

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_shr() {

  auto dest = 0 + (instruction.mnemonic == Mnemonic::SARX);
  auto count = 1 + (instruction.mnemonic == Mnemonic::SARX);

  Value* Lvalue = GetIndexValue(dest);
  Value* countValue = GetIndexValue(count);
  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  unsigned maskC = bitWidth == 64 ? 0x3f : 0x1f;

  Value* clampedCount = createAndFolder(
      countValue, ConstantInt::get(countValue->getType(), maskC), "shrclamp");

  Value* result =
      createLShrFolder(Lvalue, clampedCount,
                       "shr-lshr-" + std::to_string(current_address) + "-");

  Value* zero = ConstantInt::get(countValue->getType(), 0);

  // check if count > bitwidth
  // early case

  Value* isZeroed =
      createICMPFolder(CmpInst::ICMP_UGT, clampedCount,
                       ConstantInt::get(clampedCount->getType(), bitWidth - 1));

  result = createSelectFolder(isZeroed, zero, result, "shiftValue");

  // flags
  Value* cfValue = createTruncFolder(
      createLShrFolder(
          Lvalue,
          createSubFolder(clampedCount,
                          ConstantInt::get(clampedCount->getType(), 1)),
          "shrcf"),
      builder->getInt1Ty());

  Value* isCountOne =
      createICMPFolder(CmpInst::ICMP_EQ, clampedCount,
                       ConstantInt::get(clampedCount->getType(), 1));

  Value* of = createICMPFolder(CmpInst::ICMP_SLT, Lvalue,
                               ConstantInt::get(Lvalue->getType(), 0));

  of = createSelectFolder(isCountOne, of, getFlag(FLAG_OF), "of");

  Value* isNotZero = createICMPFolder(CmpInst::ICMP_NE, clampedCount, zero);

  Value* oldcf = getFlag(FLAG_CF);

  cfValue = createSelectFolder(isNotZero, cfValue, oldcf, "cfValue1");

  Value* sf =
      createSelectFolder(isNotZero, computeSignFlag(result), getFlag(FLAG_SF));

  Value* zf =
      createSelectFolder(isNotZero, computeZeroFlag(result), getFlag(FLAG_ZF));

  Value* pf = createSelectFolder(isNotZero, computeParityFlag(result),
                                 getFlag(FLAG_PF));

  printvalue(sf);
  printvalue(result);

  if (instruction.mnemonic != Mnemonic::SHRX) {
    setFlag(FLAG_CF, cfValue);
    setFlag(FLAG_OF, of);
    setFlag(FLAG_SF, sf);
    setFlag(FLAG_ZF, zf);
    setFlag(FLAG_PF, pf);
  }
  printvalue(Lvalue) printvalue(clampedCount) printvalue(result);
  printvalue(isNotZero) printvalue(oldcf) printvalue(cfValue);

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_shl() {
  LLVMContext& context = builder->getContext();

  printvalue2(finished);

  auto dest = 0 + (instruction.mnemonic == Mnemonic::SARX);
  auto count = 1 + (instruction.mnemonic == Mnemonic::SARX);
  Value* Lvalue = GetIndexValue(dest);
  Value* countValue = GetIndexValue(count);
  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  unsigned maskC = bitWidth == 64 ? 0x3f : 0x1f;

  auto bitWidthValue = ConstantInt::get(countValue->getType(), bitWidth);

  Value* clampedCountValue = createAndFolder(
      countValue, ConstantInt::get(countValue->getType(), maskC), "shlclamp");
  printvalue(clampedCountValue);

  Value* result = createShlFolder(Lvalue, clampedCountValue, "shl-shift");
  Value* zero = ConstantInt::get(countValue->getType(), 0);
  Value* isZeroed = createICMPFolder(
      CmpInst::ICMP_UGT, clampedCountValue,
      ConstantInt::get(clampedCountValue->getType(), bitWidth - 1));
  result = createSelectFolder(isZeroed, zero, result);

  Value* cfValue = createLShrFolder(
      Lvalue, createSubFolder(bitWidthValue, clampedCountValue), "shlcf");
  Value* one = ConstantInt::get(cfValue->getType(), 1);
  cfValue = createAndFolder(cfValue, one, "shlcf");
  cfValue = createZExtOrTruncFolder(cfValue, Type::getInt1Ty(context));

  auto countIsNotZero =
      createICMPFolder(CmpInst::ICMP_NE, clampedCountValue,
                       ConstantInt::get(clampedCountValue->getType(), 0));

  auto cfRvalue = createSubFolder(
      clampedCountValue, ConstantInt::get(clampedCountValue->getType(), 1));
  auto cfShl = createShlFolder(Lvalue, cfRvalue);
  auto cfIntT = cast<IntegerType>(cfShl->getType());
  auto cfRightCount = ConstantInt::get(cfIntT, cfIntT->getBitWidth() - 1);
  auto cfLow = createLShrFolder(cfShl, cfRightCount, "lowcfshr");
  cfValue = createSelectFolder(
      countIsNotZero, createZExtOrTruncFolder(cfLow, Type::getInt1Ty(context)),
      getFlag(FLAG_CF));

  Value* isCountOne =
      createICMPFolder(CmpInst::ICMP_EQ, clampedCountValue,
                       ConstantInt::get(clampedCountValue->getType(), 1));

  Value* originalMSB = createLShrFolder(
      Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1), "shlmsb");
  originalMSB = createAndFolder(
      originalMSB, ConstantInt::get(Lvalue->getType(), 1), "shlmsb");
  originalMSB = createZExtOrTruncFolder(originalMSB, Type::getInt1Ty(context));

  Value* cfAsMSB = createZExtOrTruncFolder(
      createLShrFolder(Lvalue,
                       ConstantInt::get(Lvalue->getType(), bitWidth - 1),
                       "shlcfasmsb"),
      Type::getInt1Ty(context));

  Value* resultMSB = createZExtOrTruncFolder(
      createLShrFolder(result,
                       ConstantInt::get(result->getType(), bitWidth - 1),
                       "shlresultmsb"),
      Type::getInt1Ty(context));

  Value* ofValue = createSelectFolder(
      isCountOne, createXorFolder(resultMSB, cfAsMSB), getFlag(FLAG_OF));

  if (instruction.mnemonic != Mnemonic::SHLX) {
    setFlag(FLAG_CF, cfValue);
    setFlag(FLAG_OF, ofValue);

    Value* sf = createSelectFolder(countIsNotZero, computeSignFlag(result),
                                   getFlag(FLAG_SF));
    Value* oldpf = getFlag(FLAG_PF);
    printvalue(Lvalue);
    printvalue(countValue);
    printvalue(clampedCountValue);
    printvalue(isCountOne);
    printvalue(result);
    printvalue(ofValue);
    printvalue(cfValue);

    setFlag(FLAG_SF, sf);
    auto oldZF = getLazyFlag(FLAG_ZF);
    setFlag(FLAG_ZF, [this, countIsNotZero, result, oldZF]() mutable {
      return createSelectFolder(countIsNotZero, computeZeroFlag(result),
                                oldZF.get());
    });
    setFlag(FLAG_PF, [this, result, oldpf, countIsNotZero]() {
      return createSelectFolder(countIsNotZero, computeParityFlag(result),
                                oldpf);
    });
  }
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bswap() {
  // auto dest = operands[0];

  auto Lvalue = GetIndexValue(0);
  // if 16bit, 0 it

  auto destsize = GetTypeSize(instruction.types[0]);

  // smarter check for size
  if (destsize == 16) {
    Value* zero = ConstantInt::get(Lvalue->getType(), 0);
    SetIndexValue(0, zero);
    return;
  }

  Value* newswappedvalue = ConstantInt::get(Lvalue->getType(), 0);
  Value* mask = ConstantInt::get(Lvalue->getType(), 0xff);

  // use intrinsic?

  for (unsigned i = 0; i < Lvalue->getType()->getIntegerBitWidth() / 8; i++) {

    auto byte =
        createLShrFolder(createAndFolder(Lvalue, mask), i * 8, "shlresultmsb");
    auto shiftby = Lvalue->getType()->getIntegerBitWidth() - (i + 1) * 8;
    auto newposbyte = createShlFolder(byte, shiftby);
    newswappedvalue = createOrFolder(newswappedvalue, newposbyte);
    mask = createShlFolder(mask, 8);
  }

  SetIndexValue(0, newswappedvalue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmpxchg() {
  /*
    auto dest = operands[0];
    auto src = operands[1];
    auto accop = operands[2];
   */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Register accreg =
      GetAccumulatorRegister(Lvalue->getType()->getIntegerBitWidth());
  auto accum =
      GetRegisterValue(accreg); // accumulator register, get depending on size?
  printvalue2(magic_enum::enum_name(accreg));
  printvalue(accum);
  printvalue(Rvalue);
  printvalue(Lvalue);

  auto sub = createSubFolder(accum, Lvalue);

  // ???
  auto of = computeOverflowFlagSub(accum, Lvalue, sub);

  auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
  auto RvalueLowerNibble =
      createAndFolder(accum, lowerNibbleMask, "lvalLowerNibble");
  auto op2LowerNibble =
      createAndFolder(Lvalue, lowerNibbleMask, "rvalLowerNibble");

  auto cf = createICMPFolder(CmpInst::ICMP_UGT, Lvalue, accum, "add_cf");
  auto af = createICMPFolder(CmpInst::ICMP_ULT, RvalueLowerNibble,
                             op2LowerNibble, "add_af");

  auto sf = computeSignFlag(sub);

  /*
  TEMP := DEST
  IF accumulator = TEMP
          THEN
                  ZF := 1;
                  DEST := SRC;
          ELSE
                  ZF := 0;
                  accumulator := TEMP;
                  DEST := TEMP;
  FI;
  */
  auto zf = createICMPFolder(CmpInst::ICMP_EQ, accum, Lvalue);
  // if zf dest = src
  auto result = createSelectFolder(zf, Rvalue, Lvalue);
  auto acc = createSelectFolder(zf, accum, Lvalue);
  SetRegisterValue(accreg, acc);
  SetIndexValue(0, result);
  setFlag(FLAG_OF, of);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_AF, af);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_xchg() {
  /*
    auto dest = operands[0];
    auto src = operands[1];
  */

  auto Rvalue = GetIndexValue(1);
  auto Lvalue = GetIndexValue(0);

  printvalue(Lvalue) printvalue(Rvalue);

  SetIndexValue(0, Rvalue);
  SetIndexValue(1, Lvalue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_popcnt() {
  /*
  auto dest = operands[0]; // count
  auto src = operands[1];  // src
   */

  auto srcV = GetIndexValue(1);
  printvalue(srcV); // if src is 0, count 0

  // create intrinsic for popct
  auto popcnt =
      Intrinsic::getDeclaration(builder->GetInsertBlock()->getModule(),
                                Intrinsic::ctpop, srcV->getType());
  Value* popcntV = nullptr;

  if (isa<ConstantInt>(srcV)) {
    popcntV =
        builder->getIntN(srcV->getType()->getIntegerBitWidth(),
                         popcount(cast<ConstantInt>(srcV)->getZExtValue()));
  } else {
    popcntV = builder->CreateCall(popcnt, {srcV});
  }
  auto destV = simplifyValue(
      popcntV,
      builder->GetInsertBlock()->getParent()->getParent()->getDataLayout());
  printvalue(destV);

  setFlag(FLAG_OF, builder->getInt1(0));

  setFlag(FLAG_SF, builder->getInt1(0));

  setFlag(FLAG_ZF, computeZeroFlag(destV));

  setFlag(FLAG_AF, builder->getInt1(0));

  setFlag(FLAG_CF, builder->getInt1(0));

  setFlag(FLAG_PF, builder->getInt1(0));

  SetIndexValue(0, destV);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_shld() {
  LLVMContext& context = builder->getContext();

  /*
  auto dest = operands[0];
  auto source = operands[1];
  auto count = operands[2];
  */
  auto Lvalue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);

  auto countValue = GetIndexValue(2); // zext

  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto mask = bitWidth == 64 ? 64 : 32;
  auto effectiveCountValue = createURemFolder(
      countValue, ConstantInt::get(countValue->getType(), mask),
      "effectiveShiftCount");
  // 16 bit is usually undefined?

  auto shiftedDest =
      createShlFolder(Lvalue, effectiveCountValue, "shiftedDest");
  auto complementCount =
      createSubFolder(ConstantInt::get(countValue->getType(), bitWidth),
                      effectiveCountValue, "complementCount");
  auto shiftedSource =
      createLShrFolder(sourceValue, complementCount, "shiftedSource");
  auto resultValue = createOrFolder(shiftedDest, shiftedSource, "shldResult");

  auto countIsNotZero =
      createICMPFolder(CmpInst::ICMP_NE, effectiveCountValue,
                       ConstantInt::get(effectiveCountValue->getType(), 0));
  auto lastShiftedBitPosition = createSubFolder(
      ConstantInt::get(effectiveCountValue->getType(), bitWidth),
      effectiveCountValue);
  auto lastShiftedBit =
      createAndFolder(createLShrFolder(Lvalue, lastShiftedBitPosition),
                      ConstantInt::get(Lvalue->getType(), 1), "shldresultmsb");
  auto cf = createSelectFolder(
      countIsNotZero,
      createZExtOrTruncFolder(lastShiftedBit, Type::getInt1Ty(context)),
      getFlag(FLAG_CF));
  resultValue = createSelectFolder(countIsNotZero, resultValue, Lvalue);

  auto isOne =
      createICMPFolder(CmpInst::ICMP_EQ, effectiveCountValue,
                       ConstantInt::get(effectiveCountValue->getType(), 1));
  auto newOF = createXorFolder(
      createLShrFolder(
          Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1), "subof"),
      createLShrFolder(resultValue,
                       ConstantInt::get(resultValue->getType(), bitWidth - 1),
                       "subof2"),
      "subxorof");
  auto of = createSelectFolder(
      isOne, createZExtOrTruncFolder(newOF, Type::getInt1Ty(context)),
      getFlag(FLAG_OF));

  //  CF := BIT[DEST, SIZE – COUNT]; if shifted,
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  setFlag(FLAG_SF, computeSignFlag(resultValue));
  setFlag(FLAG_ZF, computeZeroFlag(resultValue));
  setFlag(FLAG_PF, computeParityFlag(resultValue));

  SetIndexValue(0, resultValue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_shrd() {
  LLVMContext& context = builder->getContext();

  /*  auto dest = operands[0];
   auto source = operands[1];
   auto count = operands[2]; */

  auto Lvalue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto countValue = GetIndexValue(2);

  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto mask = bitWidth == 64 ? 64 : 32;
  auto effectiveCountValue = createURemFolder(
      countValue, ConstantInt::get(countValue->getType(), mask),
      "effectiveShiftCount");
  // 16 bit is usually undefined?
  //
  auto shiftedDest =
      createLShrFolder(Lvalue, effectiveCountValue, "shiftedDest");
  auto complementCount =
      createSubFolder(ConstantInt::get(countValue->getType(), bitWidth),
                      effectiveCountValue, "complementCount");
  auto shiftedSource =
      createShlFolder(sourceValue, complementCount, "shiftedSource");
  auto resultValue = createOrFolder(shiftedDest, shiftedSource, "shrdResult");

  // Calculate CF
  // x >> 1
  // msb of x would be cf
  // so x >> 0
  // conclusion:
  // x >> (count - 1) = cf
  auto cfBitPosition = createSubFolder(
      effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
  Value* cf = createLShrFolder(Lvalue, cfBitPosition);
  cf = createAndFolder(cf, ConstantInt::get(cf->getType(), 1), "shrdcf");
  cf = createZExtOrTruncFolder(cf, Type::getInt1Ty(context));

  // Calculate OF, only when count is 1
  Value* isCountOne =
      createICMPFolder(CmpInst::ICMP_EQ, effectiveCountValue,
                       ConstantInt::get(effectiveCountValue->getType(), 1));
  Value* mostSignificantBitOfDest = createLShrFolder(
      Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1), "shlmsbdest");
  mostSignificantBitOfDest = createAndFolder(
      mostSignificantBitOfDest,
      ConstantInt::get(mostSignificantBitOfDest->getType(), 1), "shrdmsb");
  Value* mostSignificantBitOfResult = createLShrFolder(
      resultValue, ConstantInt::get(resultValue->getType(), bitWidth - 1),
      "shlmsbresult");
  mostSignificantBitOfResult = createAndFolder(
      mostSignificantBitOfResult,
      ConstantInt::get(mostSignificantBitOfResult->getType(), 1), "shrdmsb2");
  Value* of =
      createXorFolder(mostSignificantBitOfDest, mostSignificantBitOfResult);
  of = createZExtOrTruncFolder(of, Type::getInt1Ty(context));

  // TODO: wrapper for undef behaviour?
  of =
      createSelectFolder(isCountOne, of, UndefValue::get(builder->getInt1Ty()));
  of = createZExtFolder(of, Type::getInt1Ty(context));

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  setFlag(FLAG_SF, computeSignFlag(resultValue));
  setFlag(FLAG_ZF, computeZeroFlag(resultValue));
  setFlag(FLAG_PF, computeParityFlag(resultValue));

  SetIndexValue(0, resultValue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_lea() {
  /*
    auto dest = operands[0];
    auto src = operands[1]; */

  auto destsize = GetTypeSize(instruction.types[0]);

  auto Rvalue = createZExtOrTruncFolder(GetEffectiveAddress(),
                                        builder->getIntNTy(destsize));

  printvalue(Rvalue);

  SetIndexValue(0, Rvalue);
}

// extract sub from this function, this is convoluted for no reason
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_add_sub() {
  /* auto dest = operands[0];
  auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  Value* result = nullptr;

  switch (instruction.mnemonic) {
  case Mnemonic::ADD: {
    result = createAddFolder(
        Lvalue, Rvalue, "realadd-" + std::to_string(current_address) + "-");

    setFlag(FLAG_AF, [this, Lvalue, Rvalue]() {
      auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
      auto RvalueLowerNibble =
          createAndFolder(Lvalue, lowerNibbleMask, "lvalLowerNibble");
      auto op2LowerNibble =
          createAndFolder(Rvalue, lowerNibbleMask, "rvalLowerNibble");
      auto sumLowerNibble = createAddFolder(RvalueLowerNibble, op2LowerNibble,
                                            "add_sumLowerNibble");
      return createICMPFolder(CmpInst::ICMP_UGT, sumLowerNibble,
                              lowerNibbleMask, "add_af");
    });
    setFlag(FLAG_CF, [this, result, Lvalue, Rvalue]() {
      return createOrFolder(
          createICMPFolder(CmpInst::ICMP_ULT, result, Lvalue, "add_cf1"),
          createICMPFolder(CmpInst::ICMP_ULT, result, Rvalue, "add_cf2"),
          "add_cf");
    });
    setFlag(FLAG_OF, [this, result, Lvalue, Rvalue]() {
      return computeOverflowFlagAdd(Lvalue, Rvalue, result);
    });
    break;
  }
  case Mnemonic::SUB: {
    result = createSubFolder(
        Lvalue, Rvalue, "realsub-" + std::to_string(current_address) + "-");

    setFlag(FLAG_AF, [this, Lvalue, Rvalue]() {
      auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
      auto RvalueLowerNibble =
          createAndFolder(Lvalue, lowerNibbleMask, "lvalLowerNibble");
      auto op2LowerNibble =
          createAndFolder(Rvalue, lowerNibbleMask, "rvalLowerNibble");
      return createICMPFolder(CmpInst::ICMP_ULT, RvalueLowerNibble,
                              op2LowerNibble, "sub_af");
    });

    setFlag(FLAG_CF, [this, Lvalue, Rvalue]() {
      return createICMPFolder(CmpInst::ICMP_UGT, Rvalue, Lvalue, "add_cf");
    });

    setFlag(FLAG_OF, [this, result, Lvalue, Rvalue]() {
      return computeOverflowFlagSub(Lvalue, Rvalue, result);
    });
    break;
  }
  default:
    break;
  }

  /*
  Flags Affected
  The OF, SF, ZF, AF, CF, and PF flags are set according to the result.
  */

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });

  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });

  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(result);

  SetIndexValue(0, result);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_imul2() {
  LLVMContext& context = builder->getContext();
  // auto src = operands[0];
  auto Rvalue = GetRegisterValue(Register::AL);

  auto srcsize = GetTypeSize(instruction.types[0]);

  Value* Lvalue = GetIndexValue(0);

  Lvalue = createSExtFolder(Lvalue, Type::getIntNTy(context, srcsize * 2));

  Rvalue = createSExtOrTruncFolder(
      Rvalue, Type::getIntNTy(context,
                              srcsize)); // make sure the size is correct,
                                         // 1 byte, GetRegisterValue doesnt
                                         // ensure we have the correct size
  Rvalue = createSExtOrTruncFolder(Rvalue, Lvalue->getType());

  Value* result = createMulFolder(Rvalue, Lvalue);
  Value* lowerresult = createTruncFolder(
      result, Type::getIntNTy(context, srcsize), "lowerResult");
  Value* of;
  Value* cf;

  of = createICMPFolder(CmpInst::ICMP_NE, result,
                        createSExtFolder(lowerresult, result->getType()));
  cf = of;

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);
  printvalue(cf);
  printvalue(of);
  SetRegisterValue(Register::AX, result);
  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(result);
  // if imul modify cf and of flags
  // if not, dont do anything else
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_mul2() {
  LLVMContext& context = builder->getContext();
  // auto src = operands[0];
  auto Rvalue = GetRegisterValue(Register::AL);

  auto srcsize = GetTypeSize(instruction.types[0]);

  Value* Lvalue = GetIndexValue(0);

  Lvalue = createZExtFolder(Lvalue, Type::getIntNTy(context, srcsize * 2));

  Rvalue = createZExtOrTruncFolder(
      Rvalue, Type::getIntNTy(context,
                              srcsize)); // make sure the size is correct, 1
                                         // byte, GetRegisterValue doesnt
                                         // ensure we have the correct size
  Rvalue = createZExtOrTruncFolder(Rvalue, Lvalue->getType());

  Value* result = createMulFolder(Rvalue, Lvalue);

  Value* of;
  Value* cf;

  Value* highPart = createLShrFolder(result, srcsize, "highPart");
  Value* highPartTruncated = createTruncFolder(
      highPart, Type::getIntNTy(context, srcsize), "truncatedHighPart");
  cf = createICMPFolder(CmpInst::ICMP_NE, highPartTruncated,
                        ConstantInt::get(result->getType(), 0), "cf");
  of = cf;

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);
  printvalue(cf);
  printvalue(of);
  SetRegisterValue(Register::AX, result);
  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(result);
  // if imul modify cf and of flags
  // if not, dont do anything else
}

// TODO rewrite this

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_imul() {
  LLVMContext& context = builder->getContext();

  auto destsize = GetTypeSize(instruction.types[0]);
  printvalue2(destsize);
  printvalue2(instruction.operand_count_visible);
  if (destsize == 8 && instruction.operand_count_visible == 1) {
    lift_imul2();
    return;
  }

  // switch case?
  Value* Lvalue; // = GetIndexValue(src);
  Value* Rvalue; // = GetIndexValue(src2);

  switch (instruction.operand_count_visible) {
  case 3:
    Lvalue = GetIndexValue(2);
    Rvalue = GetIndexValue(1);
    break;
  case 2:
    Lvalue = GetIndexValue(1);
    Rvalue = GetIndexValue(0);
    break;
  case 1:
    Lvalue = GetIndexValue(0);
    Rvalue = GetRegisterValue(getRegOfSize(Register::RAX, destsize));
    printvalue(Rvalue);
    printvalue2(destsize);
    break;
  default:
    UNREACHABLE("impossible count");
  }

  // Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  auto srcsize = GetTypeSize(instruction.types[0]);
  uint8_t initialSize = srcsize;
  printvalue2(initialSize);
  printvalue(Rvalue);
  printvalue(Lvalue);
  Rvalue = createSExtFolder(Rvalue, Type::getIntNTy(context, initialSize * 2));
  Lvalue = createSExtFolder(Lvalue, Type::getIntNTy(context, initialSize * 2));

  Value* result = createMulFolder(Lvalue, Rvalue, "intmul");
  printvalue(result);
  // Flags

  Value* highPart = createLShrFolder(result, initialSize, "highPart");
  Value* highPartTruncated = createTruncFolder(
      highPart, Type::getIntNTy(context, initialSize), "truncatedHighPart");
  printvalue(highPart);
  printvalue(highPartTruncated);
  /*
  For the one operand form of the instruction, the CF and OF flags are set
  when significant bits are carried into the upper half of the result and
  cleared when the result fits exactly in the lower half of the result.
  For the two- and three-operand forms of the instruction, the CF and OF
  flags are set when the result must be truncated to fit in the
  destination operand size and cleared when the result fits exactly in the
  destination operand size. The SF, ZF, AF, and PF flags are undefined.
  */

  /*
  DEST := TruncateToOperandSize(TMP_XP);
  IF SignExtend(DEST) ≠ TMP_XP
  THEN CF := 1; OF := 1;
          ELSE CF := 0; OF := 0; FI;
  */

  Value* truncresult = createTruncFolder(
      result, Type::getIntNTy(context, initialSize), "truncRes");
  printvalue(truncresult);
  Value* cf =
      createICMPFolder(CmpInst::ICMP_NE, result,
                       createSExtFolder(truncresult, result->getType()), "cf");
  Value* of = cf;

  if (instruction.operand_count_visible == 3) {
    SetIndexValue(0, truncresult);
  } else if (instruction.operand_count_visible == 2) {
    SetIndexValue(0, truncresult);
  } else { // For one operand, result goes into ?dx:?ax if not a byte
           // operation
    auto splitResult = createTruncFolder(
        result, Type::getIntNTy(context, initialSize), "splitResult");
    Value* SEsplitResult = createSExtFolder(splitResult, result->getType());
    printvalue(splitResult);
    printvalue(result);
    cf = createICMPFolder(CmpInst::ICMP_NE, SEsplitResult, result);
    of = cf;
    printvalue(of);
    printvalue(result);
    printvalue(SEsplitResult);
    auto lowreg = getRegOfSize(Register::RAX, srcsize);
    if (initialSize == 8) {

      SetRegisterValue(lowreg, result);
    } else {

      auto highreg = getRegOfSize(Register::RDX, srcsize);
      SetRegisterValue(lowreg, splitResult);
      SetRegisterValue(highreg, highPartTruncated);
    }
  }

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);
  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);
  printvalue(highPartTruncated) printvalue(of) printvalue(cf);
}
// rewrite this too
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_mul() {
  /*
  mul rdx
  [0] rdx
  [1] rax
  [2] rdx
  [3] flags
  */
  /*
  IF (Byte operation)
          THEN
                  AX := AL ∗ SRC;
          ELSE (* Word or doubleword operation *)
                  IF OperandSize = 16
                          THEN
                                  DX:AX := AX ∗ SRC;
                          ELSE IF OperandSize = 32
                                  THEN EDX:EAX := EAX ∗ SRC; FI;
                          ELSE (* OperandSize = 64 *)
                                  RDX:RAX := RAX ∗ SRC;
                  FI;
  FI;
  */

  LLVMContext& context = builder->getContext();
  // auto src = operands[0];

  auto srcsize = GetTypeSize(instruction.types[0]);
  printvalue2(srcsize);
  printvalue2(instruction.operand_count_visible);
  // visible count is always 1 for mul,

  // if srcsize is 8, we only write to AX
  if (srcsize == 8) {
    lift_mul2();
    return;
  }

  Value* Rvalue = GetIndexValue(0);
  printvalue(Rvalue);
  auto keyvalue = getRegOfSize(Register::RAX, srcsize);
  printvalue2(magic_enum::enum_name(keyvalue));
  Value* Lvalue = createTruncFolder(GetRegisterValue(keyvalue),
                                    builder->getIntNTy(srcsize));
  printvalue(Lvalue);

  uint8_t initialSize = Rvalue->getType()->getIntegerBitWidth();
  printvalue2(initialSize);
  Rvalue = createZExtFolder(Rvalue, Type::getIntNTy(context, initialSize * 2));
  Lvalue = createZExtFolder(Lvalue, Type::getIntNTy(context, initialSize * 2));

  Value* result = createMulFolder(Lvalue, Rvalue, "intmul");

  // Flags
  auto resultType = Type::getIntNTy(context, initialSize);

  Value* highPart = createLShrFolder(result, initialSize, "highPart");
  Value* highPartTruncated = createTruncFolder(
      highPart, Type::getIntNTy(context, initialSize), "truncatedHighPart");

  /* The OF and CF flags are set to 0 if the upper half of the result is
   * 0; otherwise, they are set to 1. The SF, ZF, AF, and PF flags are
   * undefined.
   */
  Value* cf = createICMPFolder(CmpInst::ICMP_NE, highPartTruncated,
                               ConstantInt::get(resultType, 0), "cf");
  Value* of = cf;
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  auto splitResult = createTruncFolder(
      result, Type::getIntNTy(context, initialSize), "splitResult");
  // if not byte operation, result goes into ?dx:?ax
  auto lowreg = getRegOfSize(Register::RAX, srcsize);
  auto highreg = getRegOfSize(Register::RDX, srcsize);
  printvalue2(magic_enum::enum_name(lowreg));
  printvalue(splitResult);
  printvalue2(magic_enum::enum_name(highreg));
  printvalue(highPartTruncated);
  SetRegisterValue(lowreg, splitResult);
  SetRegisterValue(highreg, highPartTruncated);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_div() {

  LLVMContext& context = builder->getContext();
  // auto src = operands[0];

  Value *divisor, *dividend, *quotient, *remainder;

  auto srcsize = GetTypeSize(instruction.types[0]);
  auto lowreg = getRegOfSize(Register::RAX, srcsize);
  auto highreg = getRegOfSize(Register::RDX, srcsize);
  // When operand size is 8 bit
  if (srcsize == 8) {
    dividend = GetRegisterValue(Register::AX);
    divisor = GetIndexValue(0);

    divisor = createZExtFolder(divisor, Type::getIntNTy(context, srcsize * 2));
    dividend = createZExtOrTruncFolder(dividend, divisor->getType());

    remainder = createURemFolder(dividend, divisor);
    quotient = createUDivFolder(dividend, divisor);

    SetRegisterValue(
        Register::AL,
        createZExtOrTruncFolder(quotient, Type::getIntNTy(context, srcsize)));

    SetRegisterValue(
        Register::AH,
        createZExtOrTruncFolder(remainder, Type::getIntNTy(context, srcsize)));
  } else { /*
     auto dividendLowop = operands[1];  // eax
     auto dividendHighop = operands[2]; // edx */

    divisor = GetIndexValue(0);

    Value* dividendLow = GetRegisterValue(lowreg);
    Value* dividendHigh = GetRegisterValue(highreg);

    dividendLow =
        createZExtFolder(dividendLow, Type::getIntNTy(context, srcsize * 2));
    dividendHigh = createZExtFolder(dividendHigh, dividendLow->getType());
    uint8_t bitWidth = srcsize;

    dividendHigh = createShlFolder(dividendHigh, bitWidth);

    printvalue2(bitWidth);
    printvalue(dividendLow);
    printvalue(dividendHigh);

    dividend = createOrFolder(dividendHigh, dividendLow);
    printvalue(dividend);
    Value* ZExtdivisor = createZExtFolder(divisor, dividend->getType());

    if (isa<ConstantInt>(ZExtdivisor) && isa<ConstantInt>(dividend)) {

      APInt divideCI = cast<ConstantInt>(ZExtdivisor)->getValue();
      APInt dividendCI = cast<ConstantInt>(dividend)->getValue();
      // stop divide by 0
      APInt quotientCI = dividendCI.udiv(divideCI);
      APInt remainderCI = dividendCI.urem(divideCI);

      printvalue2(divideCI);
      printvalue2(dividendCI);
      printvalue2(quotientCI);
      printvalue2(remainderCI);

      quotient = ConstantInt::get(divisor->getType(), quotientCI);
      remainder = ConstantInt::get(divisor->getType(), remainderCI);
    } else {
      quotient = createUDivFolder(dividend, ZExtdivisor);
      remainder = createURemFolder(dividend, ZExtdivisor);
    }

    SetRegisterValue(lowreg,
                     createZExtOrTruncFolder(quotient, divisor->getType()));

    SetRegisterValue(highreg,
                     createZExtOrTruncFolder(remainder, divisor->getType()));
  }

  printvalue(divisor) printvalue(dividend) printvalue(remainder)
      printvalue(quotient)
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_idiv() {
  LLVMContext& context = builder->getContext();
  // auto src = operands[0];

  auto srcsize = GetTypeSize(instruction.types[0]);

  if (srcsize == 8) {
    auto dividend = GetRegisterValue(Register::AX);

    Value* divisor = GetIndexValue(0);
    divisor = createSExtFolder(divisor, Type::getIntNTy(context, srcsize * 2));
    dividend = createSExtOrTruncFolder(dividend, divisor->getType());
    Value* remainder = createSRemFolder(dividend, divisor);
    Value* quotient = createSDivFolder(dividend, divisor);

    SetRegisterValue(
        Register::AL,
        createZExtOrTruncFolder(quotient, Type::getIntNTy(context, srcsize)));

    SetRegisterValue(
        Register::AH,
        createZExtOrTruncFolder(remainder, Type::getIntNTy(context, srcsize)));

    printvalue(remainder);
    printvalue(quotient);
    printvalue(divisor);
    printvalue(dividend);
    return;
  }
  /*  auto dividendLowop = operands[1];  // eax
   auto dividendHighop = operands[2]; // edx */

  auto Rvalue = GetIndexValue(0);

  Value *dividendLow, *dividendHigh, *dividend;

  auto lowreg = getRegOfSize(Register::RAX, srcsize);
  printvalue2(magic_enum::enum_name(lowreg));
  dividendLow = GetRegisterValue(lowreg);
  printvalue(dividendLow);
  auto highreg = getRegOfSize(Register::RDX, srcsize);
  printvalue2(magic_enum::enum_name(highreg));
  dividendHigh = GetRegisterValue(highreg);
  printvalue(dividendHigh);

  dividendLow =
      createZExtFolder(dividendLow, Type::getIntNTy(context, srcsize * 2));
  dividendHigh = createZExtFolder(dividendHigh, dividendLow->getType());
  uint8_t bitWidth = srcsize;

  dividendHigh = createShlFolder(dividendHigh, bitWidth);
  printvalue2(bitWidth);
  printvalue(dividendLow);
  printvalue(dividendHigh);

  dividend = createOrFolder(dividendHigh, dividendLow);
  printvalue(dividend);
  Value* divide = createSExtFolder(Rvalue, dividend->getType());
  Value *quotient, *remainder;
  if (isa<ConstantInt>(divide) && isa<ConstantInt>(dividend)) {

    APInt divideCI = cast<ConstantInt>(divide)->getValue();
    APInt dividendCI = cast<ConstantInt>(dividend)->getValue();

    APInt quotientCI = dividendCI.sdiv(divideCI);
    APInt remainderCI = dividendCI.srem(divideCI);

    printvalue2(divideCI);
    printvalue2(dividendCI);
    printvalue2(quotientCI);
    printvalue2(remainderCI);
    quotient = ConstantInt::get(Rvalue->getType(), quotientCI);
    remainder = ConstantInt::get(Rvalue->getType(), remainderCI);
  } else {
    quotient = createSDivFolder(dividend, divide);
    remainder = createSRemFolder(dividend, divide);
  }
  SetRegisterValue(getRegOfSize(Register::RAX, srcsize),
                   createZExtOrTruncFolder(quotient, Rvalue->getType()));

  SetRegisterValue(getRegOfSize(Register::RDX, srcsize),
                   createZExtOrTruncFolder(remainder, Rvalue->getType()));

  printvalue(Rvalue) printvalue(dividend) printvalue(remainder)
      printvalue(quotient)
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_xor() {
  /* auto dest = operands[0];
  auto src = operands[1]; */
  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  auto result = createXorFolder(
      Lvalue, Rvalue, "realxor-" + std::to_string(current_address) + "-");

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  // auto pf = computeParityFlag(result);
  //  The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  //  according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_or() {
  // LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());
  auto result = createOrFolder(
      Lvalue, Rvalue, "realor-" + std::to_string(current_address) + "-");

  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(result);

  // auto pf = computeParityFlag(result);
  // The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  // according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_and() {
  // LLVMContext& context = builder->getContext();
  /*  auto dest = operands[0];
   auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  auto result = createAndFolder(
      Lvalue, Rvalue, "realand-" + std::to_string(current_address) + "-");

  // auto pf = computeParityFlag(result);

  // The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  // according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_andn() {
  // LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */
  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  auto result =
      createAndFolder(createNotFolder(Lvalue), Rvalue,
                      "realand-" + std::to_string(current_address) + "-");

  // auto pf = computeParityFlag(result);

  // The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  // according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  SetIndexValue(0, result);
}

/*

tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := MSB(DEST);
        DEST := (DEST ∗ 2) + tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;
IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := LSB(DEST);
FI;
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
FI
*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_rol() {
  LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  auto destsize = GetTypeSize(instruction.types[0]);

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createZExtFolder(Rvalue, Lvalue->getType());

  auto bitWidth = ConstantInt::get(Lvalue->getType(), destsize);
  auto countmask =
      ConstantInt::get(Lvalue->getType(), destsize == 64 ? 0x3f : 0x1f);

  auto one = ConstantInt::get(Lvalue->getType(), 1);
  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);
  Rvalue = createURemFolder(createAndFolder(Rvalue, countmask, "maskRvalue"),
                            bitWidth);

  Value* shiftedLeft = createShlFolder(Lvalue, Rvalue);

  Value* shiftedRight =
      createLShrFolder(Lvalue, createSubFolder(bitWidth, Rvalue), "rol");

  Value* result = createOrFolder(shiftedLeft, shiftedRight);

  Value* cf = createZExtOrTruncFolder(shiftedRight, Type::getInt1Ty(context));

  Value* isZeroBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, zero);
  Value* oldcf = getFlag(FLAG_CF); // undefined

  cf = createSelectFolder(isZeroBitRotation, oldcf, cf);

  result = createSelectFolder(isZeroBitRotation, Lvalue, result);
  // of = cf ^ MSB
  Value* newMSB = createLShrFolder(result, MSBpos, "rolmsb");
  auto of1 = createZExtOrTruncFolder(newMSB, Type::getInt1Ty(context));

  Value* of = createXorFolder(cf, of1);
  // crash?

  // Use Select to conditionally update OF based on whether the shift
  // amount is 1
  Value* isOneBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, one);
  Value* ofCurrent = getFlag(FLAG_OF);
  of = createSelectFolder(isOneBitRotation, of, ofCurrent);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);
  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);
  SetIndexValue(0, result);
}

/*

tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := LSB(SRC);
        DEST := (DEST / 2) + (tempCF ∗ 2SIZE);
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;
IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := MSB(DEST);
FI;
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR MSB − 1(DEST);
        ELSE OF is undefined;
FI

*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_ror() {

  LLVMContext& context = builder->getContext();
  /*
    auto dest = operands[0];

    auto src = operands[1]; */

  auto destsize = GetTypeSize(instruction.types[0]);

  auto Lvalue = GetIndexValue(0);

  auto Rvalue = GetIndexValue(1);

  Rvalue = createZExtFolder(Rvalue, Lvalue->getType());

  auto bitWidth = ConstantInt::get(Lvalue->getType(), destsize);

  auto countmask =
      ConstantInt::get(Lvalue->getType(), destsize == 64 ? 0x3f : 0x1f);

  auto one = ConstantInt::get(Lvalue->getType(), 1);

  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);

  auto secondMSBpos = ConstantInt::get(Lvalue->getType(), destsize - 2);

  printvalue(Rvalue);

  Rvalue = createURemFolder(createAndFolder(Rvalue, countmask, "maskRvalue"),
                            bitWidth);

  Value* rightshifted = createLShrFolder(Lvalue, Rvalue);

  Value* leftshifted =
      createShlFolder(Lvalue, createSubFolder(bitWidth, Rvalue));

  Value* result =
      createOrFolder(rightshifted, leftshifted,
                     "ror-" + std::to_string(current_address) + "-");

  Value* msb = createLShrFolder(result, MSBpos);
  Value* cf = createZExtOrTruncFolder(msb, Type::getInt1Ty(context), "ror-cf");

  Value* secondMsb = createLShrFolder(result, secondMSBpos, "ror2ndmsb");

  auto ofDefined =
      createZExtOrTruncFolder(createXorFolder(msb, secondMsb), cf->getType());

  auto isOneBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, one);

  auto isZeroBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, zero);
  Value* ofCurrent = getFlag(FLAG_OF);
  Value* of =
      createSelectFolder(isOneBitRotation, ofDefined, ofCurrent, "ror-of");

  cf = createSelectFolder(isZeroBitRotation, getFlag(FLAG_CF), cf);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  result = createSelectFolder(isZeroBitRotation, Lvalue, result, "ror-result");

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_inc() {
  // auto operand = operands[0];

  Value* Lvalue = GetIndexValue(0);

  Value* one = ConstantInt::get(Lvalue->getType(), 1, true);
  Value* result = createAddFolder(
      Lvalue, one, "inc-" + std::to_string(current_address) + "-");
  // Value* of = computeOverflowFlagAdd(Lvalue, one, result);
  // The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
  // according to the result.
  // treat it as add r, 1 for flags

  printvalue(Lvalue) printvalue(result);

  // Value* sf = computeSignFlag(result);
  // Value* zf = computeZeroFlag(result);
  // Value* pf = computeParityFlag(result);

  setFlag(FLAG_OF, [this, result, one, Lvalue]() {
    return computeOverflowFlagAdd(Lvalue, one, result);
  });
  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });

  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_AF, [this, Lvalue, one]() {
    auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
    auto destLowerNibble = createAndFolder(Lvalue, lowerNibbleMask, "adcdst");
    auto srcLowerNibble = one;
    auto sumLowerNibble = createAddFolder(destLowerNibble, srcLowerNibble);
    return createICMPFolder(CmpInst::ICMP_UGT, sumLowerNibble, lowerNibbleMask);
  });
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_dec() {
  // auto operand = operands[0];

  Value* Lvalue = GetIndexValue(0);

  Value* one = ConstantInt::get(Lvalue->getType(), 1, true);
  Value* result = createSubFolder(
      Lvalue, one, "dec-" + std::to_string(current_address) + "-");
  Value* of = computeOverflowFlagSub(Lvalue, one, result);

  // The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
  // according to the result.
  // treat it as sub r, 1 for flags

  printvalue(Lvalue) printvalue(result);

  Value* sf = computeSignFlag(result);
  Value* zf = computeZeroFlag(result);
  Value* pf = computeParityFlag(result);

  printvalue(sf);

  setFlag(FLAG_OF, of);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, pf);

  auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
  auto RvalueLowerNibble =
      createAndFolder(Lvalue, lowerNibbleMask, "lvalLowerNibble");
  auto op2LowerNibble = one;
  auto af = createICMPFolder(CmpInst::ICMP_ULT, RvalueLowerNibble,
                             op2LowerNibble, "sub_af");
  setFlag(FLAG_AF, af);
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_push() {
  LLVMContext& context = builder->getContext();
  /* auto src = operands[0]; // value that we are pushing
  auto dest = operands[2];
  auto rsp = operands[1]; */

  auto Rvalue = GetIndexValue(0);

  auto RspValue = GetRegisterValue(Register::RSP);

  auto destsize = instruction.stack_growth;
  printvalue2(destsize);
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    destsize); //

  auto result = createSubFolder(
      RspValue, val, "pushing_newrsp-" + std::to_string(current_address) + "-");

  printvalue(Rvalue);
  printvalue(RspValue);
  printvalue(result);

  SetRegisterValue(Register::RSP, result);
  // SetIndexValue(rsp, result, std::to_string(current_address));
  //  sub rsp 8 first,

  // sign extend
  switch (instruction.types[0]) {
  // case OperandType::Immediate64:
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32: {
    Rvalue = createSExtFolder(Rvalue,
                              builder->getIntNTy(instruction.stack_growth * 8));
    break;
  }
  default:
    break;
  }

  SetMemoryValue(getSPaddress(), Rvalue);
  // SetIndexValue(dest, Rvalue, std::to_string(current_address));
  // then mov rsp, val
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pushfq() {
  LLVMContext& context = builder->getContext();
  /* auto src = operands[2];  // value that we are pushing rflags
  auto dest = operands[1]; // [rsp]
  auto rsp = operands[0];  // rsp */

  auto Rvalue = GetRFLAGSValue();
  // auto Rvalue = GetRFLAGS(builder);
  auto RspValue = GetRegisterValue(Register::RSP);

  auto srcsize = 64; // based on bitness  ---

  auto val = ConstantInt::get(Type::getInt64Ty(context), srcsize / 8);
  auto result = createSubFolder(RspValue, val);

  SetRegisterValue(Register::RSP, result);
  // SetIndexValue(rsp, result, std::to_string(current_address));
  //  sub rsp 8 first,

  // pushFlags( dest, Rvalue,
  // std::to_string(current_address));;

  SetMemoryValue(getSPaddress(), Rvalue);
  // SetIndexValue(dest, Rvalue, std::to_string(current_address));
  // then mov rsp, val
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pop() {
  LLVMContext& context = builder->getContext();
  /* auto dest = operands[0]; // value that we are pushing
  auto src = operands[2];
  auto rsp = operands[1]; */

  auto destsize = instruction.stack_growth;

  auto Rvalue = GetMemoryValue(getSPaddress(), destsize * 8); // [rsp]

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), destsize);
  auto result = createAddFolder(RspValue, val,
                                "popping_new_rsp-" +
                                    std::to_string(current_address) + "-");

  printvalue(Rvalue) printvalue(RspValue) printvalue(result);

  SetRegisterValue(Register::RSP, result); // then add rsp 8

  SetIndexValue(0, Rvalue); // op
                            // mov val, rsp first
                            /* ???
                              Rvalue =
                                  createZExtFolder(Rvalue, builder->getIntNTy(instruction.stack_growth));
                                  */
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_leave() {
  // LLVMContext& context = builder->getContext();
  /*   auto src2 = operands[0]; // [xsp]
    auto src1 = operands[1]; // xbp
    auto dest = operands[2]; // xsp */
  // first xbp to xsp
  // then [xsp] to xbp

  auto xbp = GetIndexValue(1);

  SetIndexValue(2, xbp); // move xbp to xsp

  auto destsize = GetTypeSize(instruction.types[0]);

  auto popstack = popStack(destsize / 8);

  SetIndexValue(1, popstack); // then add rsp 8

  // mov val, rsp first
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_popfq() {
  LLVMContext& context = builder->getContext();
  /*  auto dest = operands[2]; // value that we are pushing
   auto src = operands[1];  // [rsp]
   auto rsp = operands[0];  // rsp */

  auto destsize = 64; // GetTypeSize(instruction.types[0]);

  auto Rvalue = GetMemoryValue(getSPaddress(), destsize); // [rsp]

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), destsize / 8);
  auto result = createAddFolder(
      RspValue, val, "popfq-" + std::to_string(current_address) + "-");

  SetRFLAGSValue(Rvalue);
  // mov val, rsp first
  SetRegisterValue(Register::RSP, result); // then add rsp 8
  // then add rsp 8
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_adc() {
  /*  auto dest = operands[0];
   auto src = operands[1]; */

  Value* Lvalue = GetIndexValue(0);
  Value* Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  Value* cf = getFlag(FLAG_CF);
  cf = createZExtFolder(cf, Lvalue->getType());

  Value* tempResult = createAddFolder(
      Lvalue, Rvalue, "adc-temp-" + std::to_string(current_address) + "-");
  Value* result = createAddFolder(
      tempResult, cf, "adc-result-" + std::to_string(current_address) + "-");
  // The OF, SF, ZF, AF, CF, and PF flags are set according to the result.

  printvalue(Lvalue) printvalue(Rvalue) printvalue(tempResult);
  printvalue(result);

  auto cfAfterFirstAdd =
      createOrFolder(createICMPFolder(CmpInst::ICMP_ULT, tempResult, Lvalue),
                     createICMPFolder(CmpInst::ICMP_ULT, tempResult, Rvalue));
  auto cfFinal = createOrFolder(
      cfAfterFirstAdd, createICMPFolder(CmpInst::ICMP_ULT, result, cf));

  auto af = computeAuxFlag(Lvalue, Rvalue, result);

  // auto of = computeOverflowFlagAdc(Lvalue, Rvalue, cf, result);

  Value* sf = computeSignFlag(result);
  Value* zf = computeZeroFlag(result);
  // Value* pf = computeParityFlag(result);

  setFlag(FLAG_OF, [this, Lvalue, Rvalue, result]() {
    return computeOverflowFlagAdd(Lvalue, Rvalue, result);
  });
  setFlag(FLAG_AF, af);
  setFlag(FLAG_CF, cfFinal);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);

  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_xadd() {
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Value* TEMP = createAddFolder(
      Lvalue, Rvalue, "xadd_sum-" + std::to_string(current_address) + "-");

  // only 0 could be memory, so ideally 0 should be set first?
  SetIndexValue(0, TEMP);
  SetIndexValue(1, Lvalue);
  /*
  TEMP := SRC + DEST;
  SRC := DEST;
  DEST := TEMP;
  */

  auto cf = createOrFolder(createICMPFolder(CmpInst::ICMP_ULT, TEMP, Lvalue),
                           createICMPFolder(CmpInst::ICMP_ULT, TEMP, Rvalue));

  auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
  auto destLowerNibble = createAndFolder(Lvalue, lowerNibbleMask, "xadddst");
  auto srcLowerNibble = createAndFolder(Rvalue, lowerNibbleMask, "xaddsrc");
  auto sumLowerNibble = createAddFolder(destLowerNibble, srcLowerNibble);
  auto af =
      createICMPFolder(CmpInst::ICMP_UGT, sumLowerNibble, lowerNibbleMask);

  auto resultSign = createICMPFolder(CmpInst::ICMP_SLT, TEMP,
                                     ConstantInt::get(Lvalue->getType(), 0));
  auto destSign = createICMPFolder(CmpInst::ICMP_SLT, Lvalue,
                                   ConstantInt::get(Lvalue->getType(), 0));
  auto srcSign = createICMPFolder(CmpInst::ICMP_SLT, Rvalue,
                                  ConstantInt::get(Rvalue->getType(), 0));
  auto inputSameSign = createICMPFolder(CmpInst::ICMP_EQ, destSign, srcSign);
  auto of = createAndFolder(
      inputSameSign, createICMPFolder(CmpInst::ICMP_NE, destSign, resultSign),
      "xaddof");

  Value* sf = computeSignFlag(TEMP);
  Value* zf = computeZeroFlag(TEMP);
  Value* pf = computeParityFlag(TEMP);

  setFlag(FLAG_OF, of);
  setFlag(FLAG_AF, af);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, pf);

  // The CF, PF, AF, SF, ZF, and OF flags are set according to the result
  // of the addition, which is stored in the destination operand.
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_test() {
  LLVMContext& context = builder->getContext();
  Value* Lvalue = GetIndexValue(0);
  Value* Rvalue = GetIndexValue(1);
  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());
  Value* testResult = createAndFolder(Lvalue, Rvalue, "testAnd");
  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(testResult);

  Value* of = ConstantInt::get(Type::getInt64Ty(context), 0, "of");
  Value* cf = ConstantInt::get(Type::getInt64Ty(context), 0, "cf");

  Value* sf =
      createICMPFolder(CmpInst::ICMP_SLT, testResult,
                       ConstantInt::get(testResult->getType(), 0), "sf");
  Value* zf =
      createICMPFolder(CmpInst::ICMP_EQ, testResult,
                       ConstantInt::get(testResult->getType(), 0), "zf");
  Value* pf = computeParityFlag(testResult);

  setFlag(FLAG_OF, of);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, pf);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmp() {

  Value* Lvalue = GetIndexValue(0);
  Value* Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  Value* cmpResult = createSubFolder(Lvalue, Rvalue);

  // Value* cf = createICMPFolder(CmpInst::ICMP_ULT, Lvalue, Rvalue);
  /*
  Value* zf = createICMPFolder(CmpInst::ICMP_EQ, cmpResult,
                               ConstantInt::get(cmpResult->getType(), 0));
  Value* sf = createICMPFolder(CmpInst::ICMP_SLT, cmpResult,
                               ConstantInt::get(cmpResult->getType(), 0));
  */
  // Value* pf = computeParityFlag(cmpResult);
  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(cmpResult);
  setFlag(FLAG_OF, [this, Lvalue, Rvalue, cmpResult]() {
    Value* signL = createICMPFolder(CmpInst::ICMP_SLT, Lvalue,
                                    ConstantInt::get(Lvalue->getType(), 0));
    Value* signR = createICMPFolder(CmpInst::ICMP_SLT, Rvalue,
                                    ConstantInt::get(Rvalue->getType(), 0));
    Value* signResult =
        createICMPFolder(CmpInst::ICMP_SLT, cmpResult,
                         ConstantInt::get(cmpResult->getType(), 0));

    Value* of = createOrFolder(
        createAndFolder(signL, createAndFolder(createNotFolder(signR),
                                               createNotFolder(signResult),
                                               "cmp-and1-")),
        createAndFolder(createNotFolder(signL),
                        createAndFolder(signR, signResult), "cmp-and2-"),
        "cmp-OF-or");
    return of;
  });
  setFlag(FLAG_CF, [this, Lvalue, Rvalue]() {
    return createICMPFolder(CmpInst::ICMP_ULT, Lvalue, Rvalue);
  });
  setFlag(FLAG_SF, [this, cmpResult]() { return computeSignFlag(cmpResult); });
  setFlag(FLAG_ZF, [this, cmpResult]() { return computeZeroFlag(cmpResult); });
  setFlag(FLAG_PF,
          [this, cmpResult]() { return computeParityFlag(cmpResult); });

  setFlag(FLAG_AF, [this, Lvalue, Rvalue]() {
    auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
    auto RvalueLowerNibble =
        createAndFolder(Lvalue, lowerNibbleMask, "lvalLowerNibble");
    auto op2LowerNibble =
        createAndFolder(Rvalue, lowerNibbleMask, "rvalLowerNibble");
    return createICMPFolder(CmpInst::ICMP_ULT, RvalueLowerNibble,
                            op2LowerNibble, "sub_af");
  });
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_rdtsc() {
  // cout << current_address << "\n";
  // LLVMContext& context = builder->getContext();
  // auto rdtscCall =
  //    builder->CreateIntrinsic(Intrinsic::readcyclecounter, {}, {});
  // call rdtsc ??
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cpuid() {
  LLVMContext& context = builder->getContext();

  // operands[0]  = eax
  // operands[1] = ebx
  // operands[2] = ecx
  // operands[3] = edx
  /*

  c++
  #include <intrin.h>

  int getcpuid() {
          int cpuInfo[4];
          __cpuid(cpuInfo, 1);
          return cpuInfo[0] + cpuInfo[1];
  }

  ir
  define dso_local noundef i32 @getcpuid() #0 {
    %1 = alloca [4 x i32], align 16
    %2 = getelementptr inbounds [4 x i32], ptr %1, i64 0, i64 0
    %3 = call { i32, i32, i32, i32 } asm "xchgq %rbx,
  ${1:q}\0Acpuid\0Axchgq %rbx, ${1:q}", "={ax},=r,={cx},={dx},0,2"(i32 1,
  i32 0) %4 = getelementptr inbounds [4 x i32], ptr %1, i64 0, i64 0 %5 =
  extractvalue { i32, i32, i32, i32 } %3, 0 %6 = getelementptr inbounds
  i32, ptr %4, i32 0 store i32 %5, ptr %6, align 4 %7 = extractvalue {
  i32, i32, i32, i32 } %3, 1 %8 = getelementptr inbounds i32, ptr %4, i32
  1 store i32 %7, ptr %8, align 4 %9 = extractvalue { i32, i32, i32, i32 }
  %3, 2 %10 = getelementptr inbounds i32, ptr %4, i32 2 store i32 %9, ptr
  %10, align 4 %11 = extractvalue { i32, i32, i32, i32 } %3, 3 %12 =
  getelementptr inbounds i32, ptr %4, i32 3 store i32 %11, ptr %12, align
  4

    %13 = getelementptr inbounds [4 x i32], ptr %1, i64 0, i64 0
    %14 = load i32, ptr %13, align 16

    %15 = getelementptr inbounds [4 x i32], ptr %1, i64 0, i64 1
    %16 = load i32, ptr %15, align 4
    %17 = add nsw i32 %14, %16
    ret i32 %17
  }
  opt
  define dso_local noundef i32 @getcpuid() local_unnamed_addr {
    %1 = tail call { i32, i32, i32, i32 } asm "xchgq %rbx,
  ${1:q}\0Acpuid\0Axchgq %rbx, ${1:q}", "={ax},=r,={cx},={dx},0,2"(i32 1,
  i32 0) #0 %2 = extractvalue { i32, i32, i32, i32 } %1, 1 ret i32 %2
  }

  */
  // int cpuInfo[4];
  // ArrayType* CpuInfoTy = ArrayType::get(Type::getInt32Ty(context), 4);

  Value* eax = GetRegisterValue(Register::EAX);

  // one is eax, other is always 0?
  std::vector<Type*> AsmOutputs = {
      Type::getInt32Ty(context), Type::getInt32Ty(context),
      Type::getInt32Ty(context), Type::getInt32Ty(context)};
  StructType* AsmStructType = StructType::get(context, AsmOutputs);

  std::vector<Type*> ArgTypes = {Type::getInt32Ty(context),
                                 Type::getInt32Ty(context)};

  // this is probably incorrect
  InlineAsm* IA =
      InlineAsm::get(FunctionType::get(AsmStructType, ArgTypes, false),
                     "xchgq %rbx, ${1:q}\ncpuid\nxchgq %rbx, ${1:q}",
                     "={ax},=r,={cx},={dx},0,2", true);

  std::vector<Value*> Args{eax, ConstantInt::get(eax->getType(), 0)};

  Value* cpuidCall = builder->CreateCall(IA, Args);

  Value* eaxv = builder->CreateExtractValue(cpuidCall, 0, "eax");
  Value* ebx = builder->CreateExtractValue(cpuidCall, 1, "ebx");
  Value* ecx = builder->CreateExtractValue(cpuidCall, 2, "ecx");
  Value* edx = builder->CreateExtractValue(cpuidCall, 3, "edx");

  SetRegisterValue(Register::EAX, eaxv);
  SetRegisterValue(Register::EBX, ebx);
  SetRegisterValue(Register::ECX, ecx);
  SetRegisterValue(Register::EDX, edx);
}

uint64_t alternative_pext(uint64_t source, uint64_t mask) {
  uint64_t result = 0;
  int bit_position = 0;
  for (uint64_t i = 0; i < 64; ++i) {
    if (mask & (1ULL << i)) {
      if (source & (1ULL << i)) {
        result |= (1ULL << bit_position);
      }
      ++bit_position;
    }
  }
  return result;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pext() {
  /*
   const auto dest = operands[0];
   const auto src1 = operands[1];
   const auto src2 = operands[2];
   */

  const auto src1v = GetIndexValue(1);
  const auto src2v = GetIndexValue(2);
  if (isa<ConstantInt>(src1v) && isa<ConstantInt>(src2v)) {
    const auto src1_c = cast<ConstantInt>(src1v);
    const auto src2_c = cast<ConstantInt>(src2v);
    const auto res =
        alternative_pext(src1_c->getZExtValue(), src2_c->getZExtValue());
    printvalue(src1_c);
    printvalue(src2_c);
    printvalue2(res);
    SetIndexValue(0, ConstantInt::get(src1v->getType(), res));
  } else {

    auto destsize = GetTypeSize(instruction.types[0]);
    Function* fakyu = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("pext",
                                  Type::getIntNTy(fnc->getContext(), destsize))
            .getCallee());
    auto rs = builder->CreateCall(fakyu, {src1v, src2v});
    SetIndexValue(0, createAndFolder(
                         rs, ConstantInt::get(
                                 rs->getType(),
                                 rs->getType()->getIntegerBitWidth() * 2 - 1)));
    // UNREACHABLE("lazy mf");
  }
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnz() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* zf = getFlag(FLAG_ZF);

  Value* result =
      createZExtFolder(createNotFolder(zf), Type::getInt8Ty(context));

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_seto() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* of = getFlag(FLAG_OF);

  Value* result = createZExtFolder(of, Type::getInt8Ty(context));

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setno() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* of = getFlag(FLAG_OF);

  Value* notOf = createNotFolder(of, "notOF");

  Value* result = createZExtFolder(notOf, Type::getInt8Ty(context));

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnb() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* cf = getFlag(FLAG_CF);

  Value* result = createICMPFolder(
      CmpInst::ICMP_EQ, cf, ConstantInt::get(Type::getInt1Ty(context), 0));

  Value* byteResult = createZExtFolder(result, Type::getInt8Ty(context));

  SetIndexValue(0, byteResult);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setbe() {
  LLVMContext& context = builder->getContext();

  Value* cf = getFlag(FLAG_CF);
  Value* zf = getFlag(FLAG_ZF);

  Value* condition = createOrFolder(cf, zf, "setbe-or");

  Value* result = createZExtFolder(condition, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnbe() {
  LLVMContext& context = builder->getContext();

  Value* cf = getFlag(FLAG_CF);
  Value* zf = getFlag(FLAG_ZF);

  Value* condition =
      createAndFolder(createNotFolder(cf), createNotFolder(zf), "setnbe-and");

  Value* result = createZExtFolder(condition, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setns() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* sf = getFlag(FLAG_SF);

  Value* result = createICMPFolder(
      CmpInst::ICMP_EQ, sf, ConstantInt::get(Type::getInt1Ty(context), 0));

  Value* byteResult = createZExtFolder(result, Type::getInt8Ty(context));

  SetIndexValue(0, byteResult);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setp() {
  LLVMContext& context = builder->getContext();

  Value* pf = getFlag(FLAG_PF);

  Value* result = createZExtFolder(pf, Type::getInt8Ty(context));

  // auto dest = operands[0];

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnp() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];

  Value* pf = getFlag(FLAG_PF);

  Value* resultValue =
      createZExtFolder(createNotFolder(pf), Type::getInt8Ty(context));

  SetIndexValue(0, resultValue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setb() {
  LLVMContext& context = builder->getContext();

  // auto dest = operands[0];

  Value* cf = getFlag(FLAG_CF);

  Value* result = createZExtFolder(cf, Type::getInt8Ty(context));

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_sets() {
  LLVMContext& context = builder->getContext();
  Value* sf = getFlag(FLAG_SF);

  Value* result = createZExtFolder(sf, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_stosx() {

  // auto dest = operands[0]; // xdi
  Value* destValue = GetIndexValue(0);
  Value* DF = getFlag(FLAG_DF);
  // if df is 1, +
  // else -
  auto destsize = GetTypeSize(instruction.types[0]);
  auto destbitwidth = destsize;

  auto one = ConstantInt::get(DF->getType(), 1);
  Value* Direction =
      createSubFolder(createMulFolder(DF, createAddFolder(DF, one)), one);

  Value* result = createAddFolder(
      destValue, createMulFolder(
                     Direction, ConstantInt::get(DF->getType(), destbitwidth)));
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setz() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];

  Value* zf = getFlag(FLAG_ZF);
  printvalue(zf);
  Value* extendedZF =
      createZExtFolder(zf, Type::getInt8Ty(context), "setz_extend");

  SetIndexValue(0, extendedZF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnle() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];

  Value* zf = getFlag(FLAG_ZF);
  Value* sf = getFlag(FLAG_SF);
  Value* of = getFlag(FLAG_OF);

  Value* zfNotSet = createICMPFolder(
      CmpInst::ICMP_EQ, zf, ConstantInt::get(Type::getInt1Ty(context), 0));

  Value* sfEqualsOf = createICMPFolder(CmpInst::ICMP_EQ, sf, of);

  printvalue(zf) printvalue(sf) printvalue(of)

      Value* combinedCondition =
          createAndFolder(zfNotSet, sfEqualsOf, "setnle-and");

  Value* byteResult =
      createZExtFolder(combinedCondition, Type::getInt8Ty(context));

  SetIndexValue(0, byteResult);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setle() {
  LLVMContext& context = builder->getContext();
  Value* zf = getFlag(FLAG_ZF);
  Value* sf = getFlag(FLAG_SF);
  Value* of = getFlag(FLAG_OF);

  Value* sf_ne_of = createICMPFolder(CmpInst::ICMP_NE, sf, of);
  Value* condition = createOrFolder(zf, sf_ne_of, "setle-or");

  Value* result = createZExtFolder(condition, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setnl() {
  LLVMContext& context = builder->getContext();
  Value* sf = getFlag(FLAG_SF);
  Value* of = getFlag(FLAG_OF);

  Value* condition = createICMPFolder(CmpInst::ICMP_EQ, sf, of);

  Value* result = createZExtFolder(condition, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setl() {
  LLVMContext& context = builder->getContext();
  Value* sf = getFlag(FLAG_SF);
  Value* of = getFlag(FLAG_OF);

  Value* condition = createICMPFolder(CmpInst::ICMP_NE, sf, of);

  Value* result = createZExtFolder(condition, Type::getInt8Ty(context));

  // auto dest = operands[0];
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bt() {
  /*
    auto dest = operands[0];
    auto bitIndex = operands[1];
   */
  // If the bit base operand specifies a register, the instruction takes
  // the modulo 16, 32, or 64 of the bit offset operand (modulo size
  // depends on the mode and register size; 64-bit operands are available
  // only in 64-bit mode). If the bit base operand specifies a memory
  // location, the operand represents the address of the byte in memory
  // that contains the bit base (bit 0 of the specified byte) of the bit
  // std::string. The range of the bit position that can be referenced by the
  // offset operand depends on the operand size. CF := Bit(BitBase,
  // BitOffset);

  auto Lvalue = GetIndexValue(0);
  auto bitIndexValue = GetIndexValue(1);

  bitIndexValue = createZExtFolder(bitIndexValue, Lvalue->getType());
  unsigned LvalueBitW = cast<IntegerType>(Lvalue->getType())->getBitWidth();

  auto Rvalue =
      createAndFolder(bitIndexValue, ConstantInt::get(bitIndexValue->getType(),
                                                      LvalueBitW - 1));

  auto shl =
      createShlFolder(ConstantInt::get(bitIndexValue->getType(), 1), Rvalue);

  auto andd = createAndFolder(shl, Lvalue);

  auto cf = createICMPFolder(CmpInst::ICMP_NE, andd,
                             ConstantInt::get(andd->getType(), 0));

  setFlag(FLAG_CF, cf);
  printvalue(Rvalue);
  printvalue(Lvalue);
  printvalue(shl);
  printvalue(andd);
  printvalue(cf);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_btr() {
  /*   auto base = operands[0];
    auto offset = operands[1]; */

  auto basesize = GetTypeSize(instruction.types[0]);
  unsigned baseBitWidth = basesize;

  Value* bitOffset = GetIndexValue(1);
  bitOffset = createZExtFolder(bitOffset, builder->getIntNTy(basesize));
  Value* bitOffsetMasked = createAndFolder(
      bitOffset, ConstantInt::get(bitOffset->getType(), baseBitWidth - 1),
      "bitOffsetMasked");

  Value* baseVal = GetIndexValue(0);

  Value* bit =
      createLShrFolder(baseVal, bitOffsetMasked,
                       "btr-lshr-" + std::to_string(current_address) + "-");

  Value* one = ConstantInt::get(bit->getType(), 1);

  bit = createAndFolder(bit, one, "btr-and");

  setFlag(FLAG_CF, bit);

  Value* mask = createShlFolder(ConstantInt::get(baseVal->getType(), 1),
                                bitOffsetMasked, "btr-shl");

  mask = createNotFolder(mask); // invert mask
  baseVal = createAndFolder(baseVal, mask,
                            "btr-and-" + std::to_string(current_address) + "-");

  SetIndexValue(0, baseVal);
  printvalue(bitOffset);
  printvalue(baseVal);
  printvalue(mask);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_lzcnt() {
  // check
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  Value* Rvalue = GetIndexValue(1);
  Value* isZero = createICMPFolder(CmpInst::ICMP_EQ, Rvalue,
                                   ConstantInt::get(Rvalue->getType(), 0));

  auto destsize = GetTypeSize(instruction.types[0]);

  Value* isOperandSize = createICMPFolder(
      CmpInst::ICMP_EQ, Rvalue, ConstantInt::get(Rvalue->getType(), destsize));
  setFlag(FLAG_ZF, isZero);
  setFlag(FLAG_CF, isOperandSize);

  unsigned bitWidth = Rvalue->getType()->getIntegerBitWidth();

  Value* index = ConstantInt::get(Rvalue->getType(), bitWidth - 1);
  Value* zeroVal = ConstantInt::get(Rvalue->getType(), 0);
  Value* oneVal = ConstantInt::get(Rvalue->getType(), 1);

  Value* bitPosition = ConstantInt::get(Rvalue->getType(), -1);

  for (unsigned i = 0; i < bitWidth; ++i) {

    Value* mask = createShlFolder(oneVal, index);

    Value* test = createAndFolder(Rvalue, mask, "bsrtest");
    Value* isBitSet = createICMPFolder(CmpInst::ICMP_NE, test, zeroVal);

    Value* tmpPosition = createSelectFolder(isBitSet, index, bitPosition);

    Value* isPositionUnset = createICMPFolder(
        CmpInst::ICMP_EQ, bitPosition, ConstantInt::get(Rvalue->getType(), -1));
    bitPosition = createSelectFolder(isPositionUnset, tmpPosition, bitPosition);

    index = createSubFolder(index, oneVal);
  }

  SetIndexValue(0, bitPosition);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bsr() {
  // check
  /*
  auto dest = operands[0];
  auto src = operands[1];
  */

  Value* Rvalue = GetIndexValue(1);
  Value* isZero = createICMPFolder(CmpInst::ICMP_EQ, Rvalue,
                                   ConstantInt::get(Rvalue->getType(), 0));
  setFlag(FLAG_ZF, isZero);

  unsigned bitWidth = Rvalue->getType()->getIntegerBitWidth();

  Value* index = ConstantInt::get(Rvalue->getType(), bitWidth - 1);
  Value* zeroVal = ConstantInt::get(Rvalue->getType(), 0);
  Value* oneVal = ConstantInt::get(Rvalue->getType(), 1);

  Value* bitPosition = ConstantInt::get(Rvalue->getType(), -1);

  for (unsigned i = 0; i < bitWidth; ++i) {

    Value* mask = createShlFolder(oneVal, index);

    Value* test = createAndFolder(Rvalue, mask, "bsrtest");
    Value* isBitSet = createICMPFolder(CmpInst::ICMP_NE, test, zeroVal);

    Value* tmpPosition = createSelectFolder(isBitSet, index, bitPosition);

    Value* isPositionUnset = createICMPFolder(
        CmpInst::ICMP_EQ, bitPosition, ConstantInt::get(Rvalue->getType(), -1));
    bitPosition = createSelectFolder(isPositionUnset, tmpPosition, bitPosition);

    index = createSubFolder(index, oneVal);
  }

  SetIndexValue(0, bitPosition);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pdep() {
  /*  auto dest = operands[0]; // destination
   auto src = operands[1];  // source
   auto mask = operands[2]; // mask */

  auto destsize = GetTypeSize(instruction.types[0]);

  unsigned operandSize = destsize; // assuming size in bits

  auto zero = builder->getIntN(operandSize, 0);
  auto one = builder->getIntN(operandSize, 1);

  auto srcV = GetIndexValue(1);
  auto maskV = GetIndexValue(2);

  // Initialize the result to zero
  Value* result = builder->getIntN(operandSize, 0);
  Value* srcPos = zero;

  // Loop over each bit position in the mask
  for (unsigned i = 0; i < operandSize; i++) {
    // Check if the current bit in the mask is set
    Value* maskBit =
        createAndFolder(createLShrFolder(maskV, i), one, "maskBit");
    Value* isMaskBitSet =
        createICMPFolder(llvm::CmpInst::ICMP_NE, maskBit, zero, "isMaskBitSet");

    // If the current bit in the mask is set, deposit the corresponding bit
    // from the source
    Value* srcBit = createAndFolder(createLShrFolder(srcV, srcPos, "srcBit"),
                                    one, "srcBit");
    Value* shiftedSrcBit = createShlFolder(
        srcBit, builder->getIntN(operandSize, i), "shiftedSrcBit");
    result =
        createSelectFolder(isMaskBitSet, createOrFolder(result, shiftedSrcBit),
                           result, "pdep_result");

    // Update the source position if the mask bit was set
    srcPos = createAddFolder(
        srcPos, createZExtFolder(isMaskBitSet, builder->getIntNTy(operandSize)),
        "srcPos");
  }

  printvalue(srcV);
  printvalue(maskV);
  printvalue(result);

  // Assign the result to the destination operand
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_blsi() {
  /*  auto tmp = operands[0];
   auto src = operands[1]; */

  Value* source = GetIndexValue(1);
  auto zero = ConstantInt::get(source->getType(), 0);
  auto temp = createAndFolder(createSubFolder(zero, source), source);

  SetIndexValue(0, temp);
  setFlag(FLAG_ZF, computeZeroFlag(temp));
  setFlag(FLAG_SF, computeSignFlag(temp));
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_blsr() {
  /* auto tmp = operands[0];
  auto src = operands[1]; */

  Value* source = GetIndexValue(1);
  auto one = ConstantInt::get(source->getType(), 1);
  auto temp = createAndFolder(createSubFolder(source, one), source);

  SetIndexValue(0, temp);
  setFlag(FLAG_ZF, computeZeroFlag(temp));
  setFlag(FLAG_SF, computeSignFlag(temp));
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_blsmsk() {
  /* auto tmp = operands[0];
  auto src = operands[1]; */

  Value* source = GetIndexValue(1);
  auto one = ConstantInt::get(source->getType(), 1);
  auto zero = ConstantInt::get(source->getType(), 0);
  auto temp = createXorFolder(createSubFolder(source, one), source);

  SetIndexValue(0, temp);
  setFlag(FLAG_ZF, zero);
  setFlag(FLAG_SF, computeSignFlag(temp));
  setFlag(FLAG_CF, createICMPFolder(llvm::CmpInst::ICMP_EQ, source, zero));
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bzhi() {
  /*
  auto dst = operands[0];
  auto src = operands[1];
  auto src2 = operands[2]; // TOFIX: this isnt used? */

  Value* source = GetIndexValue(1);

  Value* source2 = createAndFolder(
      source, builder->getIntN(source->getType()->getIntegerBitWidth(), 7));
  auto one = ConstantInt::get(source2->getType(), 1);
  auto bitmask = createAShrFolder(createShlFolder(one, source2), source2);
  auto result = createAndFolder(source, bitmask);
  SetIndexValue(0, result);
  setFlag(FLAG_ZF, computeZeroFlag(result));
  setFlag(FLAG_SF, computeSignFlag(result));
  setFlag(FLAG_OF, ConstantInt::get(source->getType(), 0));
  auto dstsize = GetTypeSize(instruction.types[0]);
  auto CF = createICMPFolder(CmpInst::ICMP_SGE, source2,
                             ConstantInt::get(source->getType(), dstsize - 1));
  setFlag(FLAG_CF, CF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bsf() {
  // TODOs
  LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  Value* Rvalue = GetIndexValue(1);

  Value* isZero = createICMPFolder(CmpInst::ICMP_EQ, Rvalue,
                                   ConstantInt::get(Rvalue->getType(), 0));
  setFlag(FLAG_ZF, isZero);

  Type* intType = Rvalue->getType();
  uint64_t intWidth = intType->getIntegerBitWidth();

  Value* result = ConstantInt::get(intType, intWidth);
  Value* one = ConstantInt::get(intType, 1);

  Value* continuecounting = ConstantInt::get(Type::getInt1Ty(context), 1);
  for (uint64_t i = 0; i < intWidth; ++i) {
    Value* bitMask =
        createShlFolder(one, ConstantInt::get(intType, i));        // a = v >> i
    Value* bitSet = createAndFolder(Rvalue, bitMask, "bsfbitset"); // b = a & 1
    Value* isBitZero = createICMPFolder(
        CmpInst::ICMP_EQ, bitSet, ConstantInt::get(intType, 0)); // c = b == 0
    // continue until isBitZero is 1
    // 0010
    // if continuecounting, select
    Value* possibleResult = ConstantInt::get(intType, i);
    Value* condition = createAndFolder(continuecounting, isBitZero,
                                       "bsfcondition"); // cond = cc, c, 0
    continuecounting = createNotFolder(isBitZero);      // cc = ~c
    result = createSelectFolder(
        condition, result, possibleResult,
        "updateResultOnFirstNonZeroBit"); // cond ift res(64) , i
  }

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_tzcnt() {
  LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  Value* Rvalue = GetIndexValue(1);

  Value* isZero = createICMPFolder(CmpInst::ICMP_EQ, Rvalue,
                                   ConstantInt::get(Rvalue->getType(), 0));
  setFlag(FLAG_ZF, isZero);

  auto srcsize = GetTypeSize(instruction.types[1]);

  Value* isEq2OperandSize = createICMPFolder(
      CmpInst::ICMP_EQ, Rvalue, ConstantInt::get(Rvalue->getType(), srcsize));

  setFlag(FLAG_CF, isEq2OperandSize);

  Type* intType = Rvalue->getType();
  uint64_t intWidth = intType->getIntegerBitWidth();

  Value* result = ConstantInt::get(intType, intWidth);
  Value* one = ConstantInt::get(intType, 1);

  Value* continuecounting = ConstantInt::get(Type::getInt1Ty(context), 1);
  for (uint64_t i = 0; i < intWidth; ++i) {
    Value* bitMask = createShlFolder(one, ConstantInt::get(intType, i));
    Value* bitSet = createAndFolder(Rvalue, bitMask, "bsfbitset");
    Value* isBitZero = createICMPFolder(CmpInst::ICMP_EQ, bitSet,
                                        ConstantInt::get(intType, 0));
    // continue until isBitZero is 1
    // 0010
    // if continuecounting, select
    Value* possibleResult = ConstantInt::get(intType, i);
    Value* condition =
        createAndFolder(continuecounting, isBitZero, "bsfcondition");
    continuecounting = createNotFolder(isBitZero);
    result = createSelectFolder(condition, result, possibleResult,
                                "updateResultOnFirstNonZeroBit");
  }

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_btc() {
  /*   auto base = operands[0];
    auto offset = operands[1]; */

  auto basesize = GetTypeSize(instruction.types[0]);
  unsigned baseBitWidth = basesize;

  Value* bitOffset = GetIndexValue(1);

  bitOffset = createZExtFolder(bitOffset, builder->getIntNTy(basesize));
  Value* bitOffsetMasked = createAndFolder(
      bitOffset, ConstantInt::get(bitOffset->getType(), baseBitWidth - 1),
      "bitOffsetMasked");

  Value* baseVal = GetIndexValue(0);

  Value* bit =
      createLShrFolder(baseVal, bitOffsetMasked,
                       "btc-lshr-" + std::to_string(current_address) + "-");

  Value* one = ConstantInt::get(bit->getType(), 1);

  bit = createAndFolder(bit, one, "btc-and");

  setFlag(FLAG_CF, bit);

  Value* mask = createShlFolder(ConstantInt::get(baseVal->getType(), 1),
                                bitOffsetMasked, "btc-shl");

  baseVal = createXorFolder(baseVal, mask,
                            "btc-and-" + std::to_string(current_address) + "-");

  SetIndexValue(0, baseVal);
  printvalue(bitOffset);
  printvalue(baseVal);
  printvalue(mask);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_lahf() {

  LLVMContext& context = builder->getContext();

  auto sf = getFlag(FLAG_SF);
  auto zf = getFlag(FLAG_ZF);
  auto af = getFlag(FLAG_AF);
  auto pf = getFlag(FLAG_PF);
  auto cf = getFlag(FLAG_CF);

  printvalue(sf) printvalue(zf) printvalue(af) printvalue(pf) printvalue(cf);

  cf = createZExtFolder(cf, Type::getInt8Ty(context));
  pf = createShlFolder(createZExtFolder(pf, Type::getInt8Ty(context)), FLAG_PF);
  af = createShlFolder(createZExtFolder(af, Type::getInt8Ty(context)), FLAG_AF);
  zf = createShlFolder(createZExtFolder(zf, Type::getInt8Ty(context)), FLAG_ZF);
  sf = createShlFolder(createZExtFolder(sf, Type::getInt8Ty(context)), FLAG_SF);
  Value* Rvalue = createAddFolder(
      createOrFolder(
          createOrFolder(createOrFolder(cf, pf), createOrFolder(af, sf)), zf),
      ConstantInt::get(cf->getType(), 2));

  printvalue(sf) printvalue(zf) printvalue(af) printvalue(pf) printvalue(cf);
  printvalue(Rvalue);
  SetRegisterValue(Register::AH, Rvalue);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_sahf() {

  auto ah = GetRegisterValue(Register::AH);
  // RFLAGS(SF:ZF:0:AF:0:PF:1:CF) := AH;
  //
  printvalue(GetRegisterValue(Register::RAX));
  printvalue(ah);
  Value* one = ConstantInt::get(ah->getType(), 1);
  auto cf = createAndFolder(
      createLShrFolder(ah, ConstantInt::get(ah->getType(), FLAG_CF)), one);
  // + 2
  auto pf = createAndFolder(
      createLShrFolder(ah, ConstantInt::get(ah->getType(), FLAG_PF)), one);
  auto af = createAndFolder(
      createLShrFolder(ah, ConstantInt::get(ah->getType(), FLAG_AF)), one);
  auto zf = createAndFolder(
      createLShrFolder(ah, ConstantInt::get(ah->getType(), FLAG_ZF)), one);
  auto sf = createAndFolder(
      createLShrFolder(ah, ConstantInt::get(ah->getType(), FLAG_SF)), one);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_PF, pf);
  setFlag(FLAG_AF, af);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_SF, sf);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_std() {
  LLVMContext& context = builder->getContext();

  setFlag(FLAG_DF, ConstantInt::get(Type::getInt1Ty(context), 1));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_stc() {
  LLVMContext& context = builder->getContext();

  setFlag(FLAG_CF, ConstantInt::get(Type::getInt1Ty(context), 1));
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmc() {

  Value* cf = getFlag(FLAG_CF);

  Value* one = ConstantInt::get(cf->getType(), 1);

  setFlag(FLAG_CF, createXorFolder(cf, one));
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_clc() {

  LLVMContext& context = builder->getContext();

  Value* clearedCF = ConstantInt::get(Type::getInt1Ty(context), 0);

  setFlag(FLAG_CF, clearedCF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cld() {

  LLVMContext& context = builder->getContext();

  Value* clearedDF = ConstantInt::get(Type::getInt1Ty(context), 0);

  setFlag(FLAG_DF, clearedDF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cli() {

  LLVMContext& context = builder->getContext();

  Value* resetIF = ConstantInt::get(Type::getInt1Ty(context), 0);

  setFlag(FLAG_IF, resetIF);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bts() {
  /*   auto base = operands[0];
    auto offset = operands[1]; */

  auto basesize = GetTypeSize(instruction.types[0]);
  unsigned baseBitWidth = basesize;

  Value* bitOffset = GetIndexValue(1);

  bitOffset = createZExtFolder(bitOffset, builder->getIntNTy(basesize));
  Value* bitOffsetMasked = createAndFolder(
      bitOffset, ConstantInt::get(bitOffset->getType(), baseBitWidth - 1),
      "bitOffsetMasked");

  Value* baseVal = GetIndexValue(0);

  Value* bit =
      createLShrFolder(baseVal, bitOffsetMasked,
                       "bts-lshr-" + std::to_string(current_address) + "-");

  Value* one = ConstantInt::get(bit->getType(), 1);

  bit = createAndFolder(bit, one, "bts-and");

  setFlag(FLAG_CF, bit);

  Value* mask = createShlFolder(ConstantInt::get(baseVal->getType(), 1),
                                bitOffsetMasked, "bts-shl");

  baseVal = createOrFolder(baseVal, mask,
                           "bts-or-" + std::to_string(current_address) + "-");

  SetIndexValue(0, baseVal);
  printvalue(bitOffset);
  printvalue(baseVal);
  printvalue(mask);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cwd() {
  LLVMContext& context = builder->getContext();

  Value* ax = createZExtOrTruncFolder(GetRegisterValue(Register::AX),
                                      Type::getInt16Ty(context));

  Value* signBit = computeSignFlag(ax);

  Value* dx = createSelectFolder(
      createICMPFolder(CmpInst::ICMP_EQ, signBit,
                       ConstantInt::get(signBit->getType(), 0)),
      ConstantInt::get(Type::getInt16Ty(context), 0),
      ConstantInt::get(Type::getInt16Ty(context), 0xFFFF), "setDX");

  SetRegisterValue(Register::DX, dx);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cdq() {
  LLVMContext& context = builder->getContext();
  // if eax is -, then edx is filled with ones FFFF_FFFF

  Value* eax = createZExtOrTruncFolder(GetRegisterValue(Register::EAX),
                                       Type::getInt32Ty(context));

  Value* signBit = computeSignFlag(eax);

  Value* edx = createSelectFolder(
      createICMPFolder(CmpInst::ICMP_EQ, signBit,
                       ConstantInt::get(signBit->getType(), 0)),
      ConstantInt::get(Type::getInt32Ty(context), 0),
      ConstantInt::get(Type::getInt32Ty(context), 0xFFFFFFFF), "setEDX");

  SetRegisterValue(Register::EDX, edx);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cqo() {

  LLVMContext& context = builder->getContext();
  // if rax is -, then rdx is filled with ones FFFF_FFFF_FFFF_FFFF
  Value* rax = createZExtOrTruncFolder(GetRegisterValue(Register::RAX),
                                       Type::getInt64Ty(context));

  Value* signBit = computeSignFlag(rax);

  Value* rdx = createSelectFolder(
      createICMPFolder(CmpInst::ICMP_EQ, signBit,
                       ConstantInt::get(signBit->getType(), 0)),
      ConstantInt::get(Type::getInt64Ty(context), 0),
      ConstantInt::get(Type::getInt64Ty(context), 0xFFFFFFFFFFFFFFFF),
      "setRDX");
  printvalue(rax) printvalue(signBit) printvalue(rdx);

  SetRegisterValue(Register::RDX, rdx);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cbw() {
  LLVMContext& context = builder->getContext();
  Value* al = createZExtOrTruncFolder(GetRegisterValue(Register::AL),
                                      Type::getInt8Ty(context));

  Value* ax = createSExtFolder(al, Type::getInt16Ty(context), "cbw");

  SetRegisterValue(Register::AX, ax);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cwde() {
  LLVMContext& context = builder->getContext();
  Value* ax = createZExtOrTruncFolder(GetRegisterValue(Register::AX),
                                      Type::getInt16Ty(context));
  printvalue(ax);
  Value* eax = createSExtFolder(ax, Type::getInt32Ty(context), "cwde");
  printvalue(eax);

  SetRegisterValue(Register::EAX, eax);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cdqe() {
  LLVMContext& context = builder->getContext();

  Value* eax = createZExtOrTruncFolder(GetRegisterValue(Register::EAX),
                                       Type::getInt32Ty(context), "cdqe-trunc");

  Value* rax = createSExtFolder(eax, Type::getInt64Ty(context), "cdqe");

  SetRegisterValue(Register::RAX, rax);
}

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