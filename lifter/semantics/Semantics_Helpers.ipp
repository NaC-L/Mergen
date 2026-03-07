// Semantics_Helpers.ipp — Flag computation, branch helper, call support
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
    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:
      bitWidth = 8;
      break;
    case ArgType::I16:
      bitWidth = 16;
      break;
    case ArgType::I32:
      bitWidth = 32;
      break;
    case ArgType::I64:
      bitWidth = 64;
      break;
    case ArgType::I128:
      bitWidth = 128;
      break;
    default:
      bitWidth = 64;
      break;
    }

    llvm::Type* type = llvm::Type::getIntNTy(context, bitWidth);
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

    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:
      bitWidth = 8;
      break;
    case ArgType::I16:
      bitWidth = 16;
      break;
    case ArgType::I32:
      bitWidth = 32;
      break;
    case ArgType::I64:
      bitWidth = 64;
      break;
    case ArgType::I128:
      bitWidth = 128;
      break;
    default:
      bitWidth = 64;
      break;
    }

    argValue =
        createZExtOrTruncFolder(argValue, Type::getIntNTy(context, bitWidth));
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
  PATH_info pathInfo = solvePath(function, destination, next_jump);
  this->hadConditionalBranch = true;
  this->lastConditionalBranchResolved = (pathInfo != PATH_unsolved);

  if (!this->lastConditionalBranchResolved) {
    // Direction is unresolved/symbolic; do not infer taken/not-taken from default destination.
    this->lastBranchTaken = false;
  } else if (true_jump_addr == false_jump_addr) {
    if (auto* condConst = llvm::dyn_cast<llvm::ConstantInt>(condition)) {
      const bool condValue = condConst->isOne();
      this->lastBranchTaken = reverse ? !condValue : condValue;
    } else {
      // Ambiguous when both destinations are equal and condition is symbolic.
      this->lastBranchTaken = false;
      this->lastConditionalBranchResolved = false;
    }
  } else {
    this->lastBranchTaken = (destination == true_jump_addr);
  }

  block->setName("previousjmp_block-" + std::to_string(destination) + "-");
  // cout << "pathInfo:" << pathInfo << " dest: " << destination  <<
  // "\n";
}
