// Semantics_Arithmetic.ipp — Arithmetic, shift, rotate, multiply, divide
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

  // OF is defined for all non-zero counts; for count=0 it's preserved below.
  auto isCountNotZero = createICMPFolder(CmpInst::ICMP_NE, actualCount, zero);
  auto newOF = createSelectFolder(isCountNotZero, ofDefined, getFlag(FLAG_OF));

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

  const bool isThreeOperandShift = instruction.mnemonic == Mnemonic::SARX ||
                                  instruction.mnemonic == Mnemonic::SHRX;
  auto source = 0 + isThreeOperandShift;
  auto count = 1 + isThreeOperandShift;

  Value* Lvalue = GetIndexValue(source);
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

  Value* isNotZero = createICMPFolder(CmpInst::ICMP_NE, clampedCount, zero);

  Value* originalMSB = createICMPFolder(
      CmpInst::ICMP_SLT, Lvalue, ConstantInt::get(Lvalue->getType(), 0));
  Value* of = createSelectFolder(isNotZero, originalMSB, getFlag(FLAG_OF), "of");

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

  const bool isThreeOperandShift = instruction.mnemonic == Mnemonic::SHLX;
  auto source = 0 + isThreeOperandShift;
  auto count = 1 + isThreeOperandShift;
  Value* Lvalue = GetIndexValue(source);
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

  Value* resultMSB = createZExtOrTruncFolder(
      createLShrFolder(result,
                       ConstantInt::get(result->getType(), bitWidth - 1),
                       "shlresultmsb"),
      Type::getInt1Ty(context));

  auto countIsOne = createICMPFolder(
      CmpInst::ICMP_EQ, clampedCountValue,
      ConstantInt::get(clampedCountValue->getType(), 1));
  Value* ofValue = createSelectFolder(
      countIsOne, createXorFolder(resultMSB, cfValue), getFlag(FLAG_OF));

  if (instruction.mnemonic != Mnemonic::SHLX) {
    setFlag(FLAG_CF, cfValue);
    setFlag(FLAG_OF, ofValue);

    Value* sf = createSelectFolder(countIsNotZero, computeSignFlag(result),
                                   getFlag(FLAG_SF));
    Value* oldpf = getFlag(FLAG_PF);
    printvalue(Lvalue);
    printvalue(countValue);
    printvalue(clampedCountValue);
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
  // When operand 0 is memory, write it before the accumulator: the memory
  // address may reference RAX/EAX, which SetRegisterValue would corrupt.
  // When operand 0 is a register, write accumulator first so DEST wins if
  // DEST aliases the accumulator (e.g., cmpxchg rax, rbx).
  auto destType = instruction.types[0];
  bool destIsMemory = destType == OperandType::Memory8 ||
                      destType == OperandType::Memory16 ||
                      destType == OperandType::Memory32 ||
                      destType == OperandType::Memory64;
  if (destIsMemory) {
    SetIndexValue(0, result);
    SetRegisterValue(accreg, acc);
  } else {
    SetRegisterValue(accreg, acc);
    SetIndexValue(0, result);
  }
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
  auto destV = popcntV;
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

  auto Lvalue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto countValue = GetIndexValue(2);

  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto mask = bitWidth == 64 ? 64 : 32;
  auto effectiveCountValue = createURemFolder(
      countValue, ConstantInt::get(countValue->getType(), mask),
      "effectiveShiftCount");

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

  auto destMSB = createAndFolder(
      createLShrFolder(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1),
                       "shldof_dest_msb"),
      ConstantInt::get(Lvalue->getType(), 1), "shldof_dest_mask");
  auto resultMSB = createAndFolder(
      createLShrFolder(resultValue,
                       ConstantInt::get(resultValue->getType(), bitWidth - 1),
                       "shldof_result_msb"),
      ConstantInt::get(resultValue->getType(), 1), "shldof_result_mask");
  auto ofComputed = createXorFolder(destMSB, resultMSB, "shldof");
  auto of = createSelectFolder(
      countIsNotZero, createZExtOrTruncFolder(ofComputed, Type::getInt1Ty(context)),
      getFlag(FLAG_OF));

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  setFlag(FLAG_SF, createSelectFolder(
                       countIsNotZero, computeSignFlag(resultValue),
                       getFlag(FLAG_SF)));
  setFlag(FLAG_ZF, createSelectFolder(
                       countIsNotZero, computeZeroFlag(resultValue),
                       getFlag(FLAG_ZF)));
  setFlag(FLAG_PF, createSelectFolder(
                       countIsNotZero, computeParityFlag(resultValue),
                       getFlag(FLAG_PF)));

  SetIndexValue(0, resultValue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_shrd() {
  LLVMContext& context = builder->getContext();

  auto Lvalue = GetIndexValue(0);
  auto sourceValue = GetIndexValue(1);
  auto countValue = GetIndexValue(2);

  countValue = createZExtFolder(countValue, Lvalue->getType());

  unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto mask = bitWidth == 64 ? 64 : 32;
  auto effectiveCountValue = createURemFolder(
      countValue, ConstantInt::get(countValue->getType(), mask),
      "effectiveShiftCount");

  auto shiftedDest =
      createLShrFolder(Lvalue, effectiveCountValue, "shiftedDest");
  auto complementCount =
      createSubFolder(ConstantInt::get(countValue->getType(), bitWidth),
                      effectiveCountValue, "complementCount");
  auto shiftedSource =
      createShlFolder(sourceValue, complementCount, "shiftedSource");
  auto resultValue = createOrFolder(shiftedDest, shiftedSource, "shrdResult");

  auto countIsNotZero =
      createICMPFolder(CmpInst::ICMP_NE, effectiveCountValue,
                       ConstantInt::get(effectiveCountValue->getType(), 0));

  auto cfBitPosition = createSelectFolder(
      countIsNotZero,
      createSubFolder(effectiveCountValue,
                      ConstantInt::get(effectiveCountValue->getType(), 1)),
      ConstantInt::get(effectiveCountValue->getType(), 0));
  Value* cf = createLShrFolder(Lvalue, cfBitPosition);
  cf = createAndFolder(cf, ConstantInt::get(cf->getType(), 1), "shrdcf");
  cf = createZExtOrTruncFolder(cf, Type::getInt1Ty(context));
  cf = createSelectFolder(countIsNotZero, cf, getFlag(FLAG_CF));

  resultValue = createSelectFolder(countIsNotZero, resultValue, Lvalue);

  auto destMSB = createAndFolder(
      createLShrFolder(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1),
                       "shrdof_dest_msb"),
      ConstantInt::get(Lvalue->getType(), 1), "shrdof_dest_mask");
  auto resultMSB = createAndFolder(
      createLShrFolder(resultValue,
                       ConstantInt::get(resultValue->getType(), bitWidth - 1),
                       "shrdof_result_msb"),
      ConstantInt::get(resultValue->getType(), 1), "shrdof_result_mask");
  auto ofComputed = createXorFolder(destMSB, resultMSB, "shrdof");
  auto of = createSelectFolder(
      countIsNotZero, createZExtOrTruncFolder(ofComputed, Type::getInt1Ty(context)),
      getFlag(FLAG_OF));

  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  setFlag(FLAG_SF, createSelectFolder(
                       countIsNotZero, computeSignFlag(resultValue),
                       getFlag(FLAG_SF)));
  setFlag(FLAG_ZF, createSelectFolder(
                       countIsNotZero, computeZeroFlag(resultValue),
                       getFlag(FLAG_ZF)));
  setFlag(FLAG_PF, createSelectFolder(
                       countIsNotZero, computeParityFlag(resultValue),
                       getFlag(FLAG_PF)));

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

  // SF/ZF/PF are architecturally undefined but real hardware sets them
  // based on the low half of the result (the value stored in ?AX).
  setFlag(FLAG_SF, computeSignFlag(splitResult));
  setFlag(FLAG_ZF, computeZeroFlag(splitResult));
  setFlag(FLAG_PF, computeParityFlag(splitResult));
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
