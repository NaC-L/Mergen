// Semantics_Misc.ipp — BMI, SIMD basics, test/cmp, setcc, bit scan, system instructions
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_bextr() {
  auto info = GetIndexValue(2);
  auto source = GetIndexValue(1);

  auto infoType = info->getType();
  auto sourceType = source->getType();
  auto operandBitWidth = sourceType->getIntegerBitWidth();

  auto start = createAndFolder(info, ConstantInt::get(infoType, 0xFF), "bextr_start");
  auto len = createAndFolder(
      createLShrFolder(info, ConstantInt::get(infoType, 8)),
      ConstantInt::get(infoType, 0xFF), "bextr_len");

  auto startInRange = createICMPFolder(
      CmpInst::ICMP_ULT, start, ConstantInt::get(infoType, operandBitWidth),
      "bextr_start_in_range");
  auto safeStart = createSelectFolder(
      startInRange, start, ConstantInt::get(infoType, 0), "bextr_safe_start");
  auto shifted =
      createLShrFolder(source, createZExtOrTruncFolder(safeStart, sourceType),
                       "bextr_shifted");

  auto lenClamped = createSelectFolder(
      createICMPFolder(CmpInst::ICMP_UGT, len,
                       ConstantInt::get(infoType, operandBitWidth),
                       "bextr_len_gt_width"),
      ConstantInt::get(infoType, operandBitWidth), len, "bextr_len_clamped");
  auto lenClampedSource = createZExtOrTruncFolder(lenClamped, sourceType);
  auto lenIsZero = createICMPFolder(
      CmpInst::ICMP_EQ, lenClampedSource, ConstantInt::get(sourceType, 0),
      "bextr_len_is_zero");
  auto safeLen = createSelectFolder(
      lenIsZero, ConstantInt::get(sourceType, 1), lenClampedSource,
      "bextr_safe_len");

  auto maskShift = createSubFolder(
      ConstantInt::get(sourceType, operandBitWidth), safeLen, "bextr_mask_shift");
  auto maskRaw = createLShrFolder(Constant::getAllOnesValue(sourceType), maskShift,
                                  "bextr_mask_raw");
  auto mask = createSelectFolder(
      lenIsZero, ConstantInt::get(sourceType, 0), maskRaw, "bextr_mask");
  auto extracted = createAndFolder(shifted, mask, "bextr_extracted");
  auto result = createSelectFolder(
      startInRange, extracted, ConstantInt::get(sourceType, 0), "bextr_result");

  SetIndexValue(0, result);
  setFlag(FLAG_ZF, createICMPFolder(CmpInst::ICMP_EQ, result,
                                    ConstantInt::get(sourceType, 0)));
  setFlag(FLAG_CF, builder->getInt1(0));
  setFlag(FLAG_OF, builder->getInt1(0));
  setFlag(FLAG_PF, computeParityFlag(result));
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

    sourceReg = createAddFolder(sourceReg, size);
    destReg = createAddFolder(destReg, size);
    printvalue(sourceReg);
    printvalue(destReg);
    SetRegisterValue(Register::RSI, sourceReg);
    SetRegisterValue(Register::RDI, destReg);
    SetRegisterValue(Register::RCX,
                     ConstantInt::get(sizeReg->getType(), 0));
    return;
  }

  SetMemoryValue(destReg, sourceVal);

  sourceReg = createAddFolder(sourceReg, Direction);
  destReg = createAddFolder(destReg, Direction);
  printvalue(sourceReg);
  printvalue(destReg);
  SetRegisterValue(Register::RSI, sourceReg);
  SetRegisterValue(Register::RDI, destReg);

  // this doesnt set flags, so if its rep/repz/repnz, we could do a trick with
  // memcpy
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_movdqa() {
  auto destinationType = instruction.types[0];
  auto sourceType = instruction.types[1];
  bool xmmDestinationForm =
      destinationType == OperandType::Register128 &&
      (sourceType == OperandType::Register128 ||
       sourceType == OperandType::Memory128);
  bool memoryDestinationForm = destinationType == OperandType::Memory128 &&
                               sourceType == OperandType::Register128;
  if (!xmmDestinationForm && !memoryDestinationForm) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }

  auto sourceValue = GetIndexValue(1);
  SetIndexValue(0, sourceValue);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pand() {
  auto destinationType = instruction.types[0];
  auto sourceType = instruction.types[1];
  bool destinationIsXmm = destinationType == OperandType::Register128;
  bool sourceIsXmm = sourceType == OperandType::Register128 ||
                     sourceType == OperandType::Memory128;
  if (!destinationIsXmm || !sourceIsXmm) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }

  auto destinationValue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto result = createAndFolder(destinationValue, sourceValue);
  SetIndexValue(0, result);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_por() {
  auto destinationType = instruction.types[0];
  auto sourceType = instruction.types[1];
  bool destinationIsXmm = destinationType == OperandType::Register128;
  bool sourceIsXmm = sourceType == OperandType::Register128 ||
                     sourceType == OperandType::Memory128;
  if (!destinationIsXmm || !sourceIsXmm) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }

  auto destinationValue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto result = createOrFolder(destinationValue, sourceValue);
  SetIndexValue(0, result);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pxor() {
  auto destinationType = instruction.types[0];
  auto sourceType = instruction.types[1];
  bool destinationIsXmm = destinationType == OperandType::Register128;
  bool sourceIsXmm = sourceType == OperandType::Register128 ||
                     sourceType == OperandType::Memory128;
  if (!destinationIsXmm || !sourceIsXmm) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }

  auto destinationValue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto result = createXorFolder(destinationValue, sourceValue);
  SetIndexValue(0, result);
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

  // When operand 0 is memory, write it first: its effective address may
  // reference the register in operand 1. Writing operand 1 first would
  // corrupt the address computation (e.g., xadd [rsp+r8*4-0xC000], r8).
  // When both operands are registers, write SRC first so DEST wins on
  // aliased cases (e.g., xadd eax, eax → EAX must get the sum).
  auto destType = instruction.types[0];
  bool destIsMemory = destType == OperandType::Memory8 ||
                      destType == OperandType::Memory16 ||
                      destType == OperandType::Memory32 ||
                      destType == OperandType::Memory64;
  if (destIsMemory) {
    SetIndexValue(0, TEMP);
    SetIndexValue(1, Lvalue);
  } else {
    SetIndexValue(1, Lvalue);
    SetIndexValue(0, TEMP);
  }
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

  // For static lifting / deobfuscation, CPUID is an opaque value barrier.
  // Emitting inline asm makes all four output registers invisible to
  // KnownBits analysis, which poisons downstream value chains and causes
  // path solver bail-outs (e.g., VMP 3.6 ROP chain resolution fails
  // because the dispatch address becomes fully unknown).
  //
  // Fix: model CPUID as returning fixed constants.  The exact values
  // don't matter for deobfuscation — what matters is that they are
  // deterministic so the path solver can reason through them.
  // These represent a generic modern x86-64 processor (CPUID leaf 1).
  SetRegisterValue(Register::EAX,
                   ConstantInt::get(Type::getInt32Ty(context), 0x000806C1));
  SetRegisterValue(Register::EBX,
                   ConstantInt::get(Type::getInt32Ty(context), 0x00800800));
  SetRegisterValue(Register::ECX,
                   ConstantInt::get(Type::getInt32Ty(context), 0x7FFAFBBF));
  SetRegisterValue(Register::EDX,
                   ConstantInt::get(Type::getInt32Ty(context), 0xBFEBFBFF));
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
  LLVMContext& context = builder->getContext();

  int byteSizeValue = 0;
  switch (instruction.mnemonic) {
  case Mnemonic::STOSB:
    byteSizeValue = 1;
    break;
  case Mnemonic::STOSW:
    byteSizeValue = 2;
    break;
  case Mnemonic::STOSD:
    byteSizeValue = 4;
    break;
  case Mnemonic::STOSQ:
    byteSizeValue = 8;
    break;
  default:
    UNREACHABLE("unreachable case on lift_stosx");
  }

  const auto addressRegisterSize = file.getMode() == arch_mode::X64 ? 64 : 32;
  const auto addressRegister = getRegOfSize(Register::RDI, addressRegisterSize);
  const auto sourceRegister = getRegOfSize(Register::RAX, byteSizeValue * 8);

  auto destAddress = GetRegisterValue(addressRegister);
  auto sourceValue = GetRegisterValue(sourceRegister);
  auto storeType = Type::getIntNTy(context, byteSizeValue * 8);
  auto storeValue = createZExtOrTruncFolder(sourceValue, storeType);
  SetMemoryValue(destAddress, storeValue);

  Value* DF = getFlag(FLAG_DF);
  auto step = ConstantInt::get(destAddress->getType(), byteSizeValue);
  auto nextAddress = createSelectFolder(
      DF, createSubFolder(destAddress, step), createAddFolder(destAddress, step));

  SetRegisterValue(addressRegister, nextAddress);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_scasx() {
  LLVMContext& context = builder->getContext();

  int byteSizeValue = 0;
  switch (instruction.mnemonic) {
  case Mnemonic::SCASB:
    byteSizeValue = 1;
    break;
  case Mnemonic::SCASW:
    byteSizeValue = 2;
    break;
  case Mnemonic::SCASD:
    byteSizeValue = 4;
    break;
  case Mnemonic::SCASQ:
    byteSizeValue = 8;
    break;
  default:
    UNREACHABLE("unreachable case on lift_scasx");
  }

  if (instruction.attributes != InstructionPrefix::None) {
    // REP/REPE/REPNE SCAS requires loop/count semantics; reject it until
    // the lifter can model repeated scan termination correctly.
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }

  const auto addressRegisterSize = file.getMode() == arch_mode::X64 ? 64 : 32;
  const auto addressRegister = getRegOfSize(Register::RDI, addressRegisterSize);
  const auto sourceRegister = getRegOfSize(Register::RAX, byteSizeValue * 8);
  auto compareType = Type::getIntNTy(context, byteSizeValue * 8);

  auto destAddress = GetRegisterValue(addressRegister);
  auto accumValue = GetRegisterValue(sourceRegister);
  accumValue = createZExtOrTruncFolder(accumValue, compareType);
  auto memoryValue = GetMemoryValue(destAddress, byteSizeValue * 8);
  memoryValue = createZExtOrTruncFolder(memoryValue, compareType);
  auto cmpResult = createSubFolder(accumValue, memoryValue,
                                   "scas-" + std::to_string(current_address) + "-");

  setFlag(FLAG_OF, [this, accumValue, memoryValue, cmpResult]() {
    Value* signL = createICMPFolder(CmpInst::ICMP_SLT, accumValue,
                                    ConstantInt::get(accumValue->getType(), 0));
    Value* signR = createICMPFolder(CmpInst::ICMP_SLT, memoryValue,
                                    ConstantInt::get(memoryValue->getType(), 0));
    Value* signResult =
        createICMPFolder(CmpInst::ICMP_SLT, cmpResult,
                         ConstantInt::get(cmpResult->getType(), 0));

    return createOrFolder(
        createAndFolder(signL, createAndFolder(createNotFolder(signR),
                                               createNotFolder(signResult),
                                               "scas-and1-")),
        createAndFolder(createNotFolder(signL),
                        createAndFolder(signR, signResult), "scas-and2-"),
        "scas-of-or");
  });
  setFlag(FLAG_CF, [this, accumValue, memoryValue]() {
    return createICMPFolder(CmpInst::ICMP_ULT, accumValue, memoryValue);
  });
  setFlag(FLAG_SF, [this, cmpResult]() { return computeSignFlag(cmpResult); });
  setFlag(FLAG_ZF, [this, cmpResult]() { return computeZeroFlag(cmpResult); });
  setFlag(FLAG_PF, [this, cmpResult]() { return computeParityFlag(cmpResult); });
  setFlag(FLAG_AF, [this, accumValue, memoryValue]() {
    auto lowerNibbleMask = ConstantInt::get(accumValue->getType(), 0xF);
    auto lhsLowerNibble =
        createAndFolder(accumValue, lowerNibbleMask, "scas-lvalLowerNibble");
    auto rhsLowerNibble =
        createAndFolder(memoryValue, lowerNibbleMask, "scas-rvalLowerNibble");
    return createICMPFolder(CmpInst::ICMP_ULT, lhsLowerNibble, rhsLowerNibble,
                            "scas-sub_af");
  });

  Value* DF = getFlag(FLAG_DF);
  auto step = ConstantInt::get(destAddress->getType(), byteSizeValue);
  auto nextAddress = createSelectFolder(
      DF, createSubFolder(destAddress, step), createAddFolder(destAddress, step));

  SetRegisterValue(addressRegister, nextAddress);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_setz() {
  LLVMContext& context = builder->getContext();

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
  Value* source = GetIndexValue(1);
  auto zero = ConstantInt::get(source->getType(), 0);

  auto ctlzDecl = Intrinsic::getDeclaration(
      builder->GetInsertBlock()->getModule(), Intrinsic::ctlz, source->getType());
  auto isZeroUndef = ConstantInt::getFalse(builder->getContext());
  Value* lzcntValue;
  if (auto* CI = dyn_cast<ConstantInt>(source)) {
    unsigned lz = CI->getValue().countl_zero();
    lzcntValue = ConstantInt::get(source->getType(), lz);
  } else {
    lzcntValue = builder->CreateCall(ctlzDecl, {source, isZeroUndef});
  }

  SetIndexValue(0, lzcntValue);

  auto isInputZero = createICMPFolder(CmpInst::ICMP_EQ, source, zero);
  auto isOutputZero = createICMPFolder(CmpInst::ICMP_EQ, lzcntValue, zero);
  setFlag(FLAG_CF, isInputZero);
  setFlag(FLAG_ZF, isOutputZero);
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

  setFlag(FLAG_PF, computeParityFlag(bitPosition));

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
  Value* source = GetIndexValue(1);
  Value* index = GetIndexValue(2);

  auto operandBitWidth = source->getType()->getIntegerBitWidth();
  auto indexType = index->getType();
  auto index8Mask = ConstantInt::get(indexType, 0xFF);
  auto saturatedLimit = ConstantInt::get(indexType, operandBitWidth - 1);
  auto indexLow8 = createAndFolder(index, index8Mask, "bzhi_index8");

  auto indexInRange =
      createICMPFolder(CmpInst::ICMP_ULE, indexLow8, saturatedLimit, "bzhi_indexInRange");
  auto clampedIndex =
      createSelectFolder(indexInRange, indexLow8, saturatedLimit, "bzhi_clampedIndex");

  auto one = ConstantInt::get(indexType, 1);
  auto lowMask = createSubFolder(createShlFolder(one, clampedIndex), one, "bzhi_lowMask");
  auto lowMaskSized = createZExtOrTruncFolder(lowMask, source->getType());

  auto maskedResult = createAndFolder(source, lowMaskSized, "bzhi_masked");
  auto result = maskedResult;

  SetIndexValue(0, result);
  setFlag(FLAG_ZF, computeZeroFlag(result));
  setFlag(FLAG_SF, computeSignFlag(result));
  setFlag(FLAG_OF, builder->getInt1(0));
  setFlag(FLAG_CF, createNotFolder(indexInRange));
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

  setFlag(FLAG_PF, computeParityFlag(result));

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_tzcnt() {
  Value* source = GetIndexValue(1);
  auto zero = ConstantInt::get(source->getType(), 0);

  auto cttzDecl = Intrinsic::getDeclaration(
      builder->GetInsertBlock()->getModule(), Intrinsic::cttz, source->getType());
  auto isZeroUndef = ConstantInt::getFalse(builder->getContext());
  Value* tzcntValue;
  if (auto* CI = dyn_cast<ConstantInt>(source)) {
    unsigned tz = CI->getValue().countr_zero();
    tzcntValue = ConstantInt::get(source->getType(), tz);
  } else {
    tzcntValue = builder->CreateCall(cttzDecl, {source, isZeroUndef});
  }

  SetIndexValue(0, tzcntValue);

  auto isInputZero = createICMPFolder(CmpInst::ICMP_EQ, source, zero);
  auto isOutputZero = createICMPFolder(CmpInst::ICMP_EQ, tzcntValue, zero);
  setFlag(FLAG_CF, isInputZero);
  setFlag(FLAG_ZF, isOutputZero);
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
