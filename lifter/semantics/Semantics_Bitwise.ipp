// Semantics_Bitwise.ipp — Bitwise ops, rotate, inc/dec, stack push/pop
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
  // ANDN (VEX): dest = ~src1 & src2, so operands map to [dest, src1, src2].
  auto src1 = GetIndexValue(1);
  auto src2 = GetIndexValue(2);

  auto result = createAndFolder(
      createNotFolder(src1), src2,
      "realand-" + std::to_string(current_address) + "-");

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  printvalue(src1) printvalue(src2) printvalue(result);

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
  const auto stackRegisterSize = file.getMode() == arch_mode::X64 ? 64 : 32;
  const auto stackRegister = getRegOfSize(Register::RSP, stackRegisterSize);
  const auto frameRegister = getRegOfSize(Register::RBP, stackRegisterSize);

  auto frameValue = GetRegisterValue(frameRegister);
  SetRegisterValue(stackRegister, frameValue);

  auto poppedFrame = popStack(stackRegisterSize / 8);
  poppedFrame = createZExtOrTruncFolder(poppedFrame, frameValue->getType());
  SetRegisterValue(frameRegister, poppedFrame);
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
