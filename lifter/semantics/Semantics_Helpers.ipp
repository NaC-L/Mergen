// Semantics_Helpers.ipp — Flag computation, branch helper, call support

// GPR order used for unknown-call argument passing (compat mode).
// This is the canonical x64 GPR ordering without duplicates.
// The memory pointer is appended separately.
template <typename Register>
static constexpr std::array<Register, 16> kAllGPROrder = {
    Register::RAX, Register::RCX, Register::RDX, Register::RBX,
    Register::RSP, Register::RBP, Register::RSI, Register::RDI,
    Register::R8,  Register::R9,  Register::R10, Register::R11,
    Register::R12, Register::R13, Register::R14, Register::R15,
};

MERGEN_LIFTER_DEFINITION_TEMPLATES(FunctionType*)::parseArgsType(
    funcsignatures<Register>::functioninfo* funcInfo, LLVMContext& context) {
  if (!funcInfo) {
    // Unknown call: build type from ABI config.
    //
    // Compat mode: 16 GPRs (i64) + memory ptr = 17 args, returns i64.
    // Strict mode: only ABI arg registers + memory ptr, returns i64.
    //
    // Both modes include the memory pointer as the final argument
    // so the callee can model memory side effects.
    const auto fx = this->buildUnknownCallFx();
    std::vector<llvm::Type*> argTypes;

    if (this->callModelMode == CallModelMode::Compat) {
      // Pass all 16 GPRs for maximum information preservation.
      argTypes.assign(16, llvm::Type::getInt64Ty(context));
    } else {
      // Strict: only ABI argument registers.
      argTypes.assign(fx.argRegs.size(), llvm::Type::getInt64Ty(context));
    }
    // Memory pointer (always last).
    argTypes.push_back(llvm::PointerType::get(context, 0));

    return FunctionType::get(Type::getInt64Ty(context), argTypes, false);
  }

  // Known function: build type from funcInfo arg descriptors.
  std::vector<llvm::Type*> argTypes;
  for (const auto& arg : funcInfo->args) {
    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:   bitWidth = 8;   break;
    case ArgType::I16:  bitWidth = 16;  break;
    case ArgType::I32:  bitWidth = 32;  break;
    case ArgType::I64:  bitWidth = 64;  break;
    case ArgType::I128: bitWidth = 128; break;
    default:            bitWidth = 64;  break;
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

  if (!funcInfo) {
    // Unknown call: build arg list from ABI config.
    const auto fx = this->buildUnknownCallFx();
    std::vector<Value*> args;

    if (this->callModelMode == CallModelMode::Compat) {
      // Compat: pass all 16 GPRs in canonical order (no duplicates).
      for (auto reg : kAllGPROrder<Register>) {
        args.push_back(
            createZExtFolder(GetRegisterValue(reg),
                             Type::getInt64Ty(context)));
      }
    } else {
      // Strict: only ABI argument registers.
      for (auto reg : fx.argRegs) {
        args.push_back(
            createZExtFolder(GetRegisterValue(reg),
                             Type::getInt64Ty(context)));
      }
    }
    // Memory pointer (always last).
    args.push_back(memoryAlloc);
    return args;
  }

  // Known function: build args from funcInfo descriptors.
  std::vector<Value*> args;
  for (const auto& arg : funcInfo->args) {
    Value* argValue = GetRegisterValue(arg.reg);

    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:   bitWidth = 8;   break;
    case ArgType::I16:  bitWidth = 16;  break;
    case ArgType::I32:  bitWidth = 32;  break;
    case ArgType::I64:  bitWidth = 64;  break;
    case ArgType::I128: bitWidth = 128; break;
    default:            bitWidth = 64;  break;
    }

    argValue =
        createZExtOrTruncFolder(argValue, Type::getIntNTy(context, bitWidth));
    if (arg.argtype.isPtr)
      argValue = getPointer(argValue);
    args.push_back(argValue);
  }
  return args;
}

// Apply post-call ABI effects after a CreateCall for an external/unknown target.
// In compat mode: only assign return value (RAX = call result).
// In strict mode: assign return value + clobber all volatile registers.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::applyPostCallEffects(
    Value* callResult, const CallEffects<Register>& fx) {
  auto& context = builder->getContext();

  // 1. Assign return value to the ABI return register(s).
  //    For x64 MSVC and all x86 CCs, the primary return register is RAX.
  if (!fx.retRegs.empty()) {
    auto retReg = *fx.retRegs.begin();
    auto retVal = createZExtOrTruncFolder(
        callResult,
        Type::getIntNTy(context,
                        file.getMode() == arch_mode::X64 ? 64 : 32));
    SetRegisterValue(retReg, retVal);
  }

  // 2. Clobber volatile registers (strict mode only).
  //    Write UndefValue to each volatile register to model the fact that
  //    the callee may have destroyed their contents.
  //    Skip registers that are also return registers (already written above).
  for (auto reg : fx.volatileRegs) {
    if (fx.retRegs.contains(reg))
      continue;
    auto undef = llvm::UndefValue::get(
        Type::getIntNTy(context,
                        file.getMode() == arch_mode::X64 ? 64 : 32));
    SetRegisterValue(reg, undef);
  }

  // 3. Memory effects.
  //    MayReadWrite: no action needed in the current memory model (the
  //    memory pointer is passed to the callee and any alias analysis
  //    already treats external calls as opaque).
  //    Preserve: no action needed (default).
}

// Called for known-name function calls (imports, signature-matched).
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::callFunctionIR(
    const std::string& functionName,
    funcsignatures<Register>::functioninfo* funcInfo) {
  auto& context = builder->getContext();

  if (!funcInfo) {
    funcInfo = signatures.getFunctionInfo(functionName);
  }
  FunctionType* externFuncType = parseArgsType(funcInfo, context);
  auto M = builder->GetInsertBlock()->getParent()->getParent();

  Function* externFunc = cast<Function>(
      M->getOrInsertFunction(functionName, externFuncType).getCallee());
  std::vector<Value*> args = parseArgs(funcInfo);
  auto callresult = builder->CreateCall(externFunc, args);

  // Build call effects for the known call.
  // Known calls use the same ABI but with KnownByName target class.
  auto fx = this->buildUnknownCallFx();
  fx.target = CallTargetClass::KnownByName;
  applyPostCallEffects(callresult, fx);
  abi::printCallEffectsDiag(fx, current_address - instruction.length);

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
