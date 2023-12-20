#include "includes.h"
#include "OperandUtils.h"
#include "ROPdetection.h"




Value* computeParityFlag(IRBuilder<>& builder, Value* value) {
    // Extract least significant byte
    Value* lsb = builder.CreateAnd(value, ConstantInt::get(value->getType(), 0xFF),"parity-and-lsb");

    // Compute the parity using bitwise operations
    lsb = builder.CreateXor(lsb, builder.CreateLShr(lsb, 4));
    lsb = builder.CreateXor(lsb, builder.CreateLShr(lsb, 2));
    lsb = builder.CreateXor(lsb, builder.CreateLShr(lsb, 1));

    // Extract the least significant bit (this will be our PF flag)
    Value* pf = builder.CreateAnd(lsb, ConstantInt::get(lsb->getType(), 1),"parityflag");

    // Return 1 - pf to match the semantics of the PF flag (1 if even set bits)
    return builder.CreateSub(ConstantInt::get(pf->getType(), 1), pf);
}


void lift_test(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    Value* Lvalue = GetOperandValue(context,builder,instruction.operands[0], instruction.operands[0].size);
    Value* Rvalue = GetOperandValue(context,builder,instruction.operands[1], instruction.operands[0].size);

    // Compute the bitwise AND result
    Value* testResult = builder.CreateAnd(Lvalue, Rvalue,"testAnd");

    // OF and CF are cleared
    Value* of = ConstantInt::get(Type::getInt64Ty(context), 0,"of-test");
    Value* cf = ConstantInt::get(Type::getInt64Ty(context), 0,"cf-test");

    // Calculate SF, ZF, and PF based on testResult
    Value* sf = builder.CreateICmpSLT(testResult, ConstantInt::get(testResult->getType(), 0),"sf-test");
    Value* zf = builder.CreateICmpEQ(testResult, ConstantInt::get(testResult->getType(), 0),"zf-test");
    Value* pf = computeParityFlag(builder, testResult);

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
}

void lift_cmp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Compute the difference

    Value* Lvalue = GetOperandValue(context, builder, instruction.operands[0], instruction.operands[0].size);
    Value* Rvalue = GetOperandValue(context, builder, instruction.operands[1], instruction.operands[0].size);

    Value* cmpResult = builder.CreateSub(Lvalue, Rvalue);

    // Calculate flags based on cmpResult
    Value* signL = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0));
    Value* signR = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
    Value* signResult = builder.CreateICmpSLT(cmpResult, ConstantInt::get(cmpResult->getType(), 0));

    // Overflow flag: (Lsign and not Rsign and not ResultSign) or (not Lsign and Rsign and ResultSign)
    Value* of = builder.CreateOr(
        builder.CreateAnd(signL, builder.CreateAnd(builder.CreateNot(signR), builder.CreateNot(signResult),"cmp-and1-")),
        builder.CreateAnd(builder.CreateNot(signL), builder.CreateAnd(signR, signResult),"cmp-and2-"), "cmp-OF-or"
    );

    Value* cf = builder.CreateICmpULT(Lvalue, Rvalue);
    Value* zf = builder.CreateICmpEQ(cmpResult, ConstantInt::get(cmpResult->getType(), 0));
    Value* sf = builder.CreateICmpSLT(cmpResult, ConstantInt::get(cmpResult->getType(), 0));
    Value* pf = computeParityFlag(builder, cmpResult);

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
}

// cmovbe = cmovbz
void lift_cmovbz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF and CF flags from RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // Check if either ZF or CF is set
    Value* condition = builder.CreateOr(zf, cf,"cmovbz-or");

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Dvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = builder.CreateSelect(condition, Rvalue, Dvalue);

    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnbz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the carry flag (CF) and zero flag (ZF) from the EFLAGS/RFLAGS register
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // Check if neither CF nor ZF is set
    Value* nbeCondition = builder.CreateAnd(builder.CreateNot(cf), builder.CreateNot(zf), "nbeCondition");

    // If nbeCondition is true, then the result is the srcValue; otherwise, it's the destValue
    Value* resultValue = builder.CreateSelect(nbeCondition, srcValue, destValue, "cmovnbe");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}




void lift_cmovz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the zero flag (ZF) from the EFLAGS/RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // If ZF is set, then the result is the srcValue; otherwise, it's the destValue
    Value* resultValue = builder.CreateSelect(zf, srcValue, destValue, "cmovz");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}



// cmovnz = cmovne
void lift_cmovnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF flag from RFLAGS register
    Value* zf = getFlag(context,builder, GetRegisterValue(context,builder,ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    zf = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Dvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = builder.CreateSelect(zf, Rvalue, Dvalue);

    SetOperandValue(context, builder, dest, result);
}
void lift_cmovl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current values of the SF and OF flags from RFLAGS register
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // The condition is true if SF is not equal to OF
    Value* condition = builder.CreateICmpNE(sf, of);

    // Retrieve the values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = builder.CreateSelect(condition, srcValue, destValue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}


void lift_cmovb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the CF flag from RFLAGS register
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // The condition is true if CF is set (i.e., 1)
    Value* condition = builder.CreateICmpEQ(cf, ConstantInt::get(Type::getInt1Ty(context), 1));

    // Retrieve the values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = builder.CreateSelect(condition, srcValue, destValue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}


void lift_cmovnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the carry flag (CF) from the EFLAGS/RFLAGS register
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // If CF is not set, then the result is the srcValue; otherwise, it's the destValue
    Value* resultValue = builder.CreateSelect(builder.CreateNot(cf), srcValue, destValue, "cmovnb");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}



void lift_cmovns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the SF flag from RFLAGS register
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    // Check if SF is clear (i.e., 0)
    Value* condition = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Retrieve the values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = builder.CreateSelect(condition, srcValue, destValue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}
void lift_movsb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // Fetch values from SI/ESI/RSI and DI/EDI/RDI
    Value* sourceValue = GetRegisterValue(context, builder, ZYDIS_REGISTER_RSI); // Adjust based on operand size
    Value* destValue = GetRegisterValue(context, builder, ZYDIS_REGISTER_RDI);

    // Fetch the byte from source
    Value* byteToMove = builder.CreateLoad(Type::getInt8Ty(context), builder.CreateIntToPtr(sourceValue, Type::getInt8Ty(context)->getPointerTo()));

    // Store the byte to destination
    builder.CreateStore(byteToMove, builder.CreateIntToPtr(destValue, Type::getInt8Ty(context)->getPointerTo()));

    // Check the direction flag
    Value* df = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_DF);

    // Create the value to increment or decrement based on DF
    Value* offset = builder.CreateSelect(df, ConstantInt::get(sourceValue->getType(), -1), ConstantInt::get(sourceValue->getType(), 1));

    // Update SI/ESI/RSI and DI/EDI/RDI
    Value* updatedSource = builder.CreateAdd(sourceValue, offset);
    Value* updatedDest = builder.CreateAdd(destValue, offset);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RSI, updatedSource); // Adjust based on operand size
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RDI, updatedDest);
}

//cmovnl = cmovge
void lift_cmovnl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF flag from RFLAGS register
    Value* sf = getFlag(context,builder, GetRegisterValue(context,builder,ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    sf = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Dvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = builder.CreateSelect(sf, Rvalue, Dvalue);

    SetOperandValue(context, builder, dest, result);
}
void lift_cmovs(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the SF flag from RFLAGS register
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If SF is set, use srcValue, otherwise keep destValue
    Value* result = builder.CreateSelect(sf, srcValue, destValue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // Operands: the first one is the destination, and the second one is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF, SF, and OF flags from RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // The condition for CMOVNLE is (ZF = 0 AND SF = OF)
    Value* condition = builder.CreateAnd(
        builder.CreateNot(zf, "notZF"),
        builder.CreateICmpEQ(sf, of, "sf_eq_of"),
        "cmovnle_cond"
    );

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Dvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = builder.CreateSelect(condition, Rvalue, Dvalue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Fetch the ZF, SF, and OF flags
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Compute the condition (ZF = 1) or (SF != OF)
    Value* sf_neq_of = builder.CreateICmpNE(sf, of);
    Value* condition = builder.CreateOr(zf, sf_neq_of,"cmovle-or");

    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = builder.CreateSelect(condition, srcValue, destValue);

    // Update the destination operand with the result
    SetOperandValue(context, builder, dest, result);
}


void lift_sbb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);

    // Get the Carry Flag (CF)
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // Perform the subtract with borrow operation
    Value* tmpResult = builder.CreateSub(destValue, srcValue,"sbb-tempresult");
    cf = builder.CreateZExtOrTrunc(cf,tmpResult->getType() ,"sbb-getcf");
    Value* result = builder.CreateSub(tmpResult, cf,"sbb-result-" + to_string(instruction.runtime_address) + "-");

    // TODO: Update the necessary flags in RFLAGS based on the result (ZF, CF, OF, etc.)
    // ...

    SetOperandValue(context, builder, dest, result);
}

void lift_rcl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto count = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* countValue = GetOperandValue(context, builder, count, dest.size);

    // Get the Carry Flag (CF)

    auto flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* carryFlagValue = getFlag(context, builder, flags, FLAG_CF);

    Value* concatenated = builder.CreateZExt(destValue, Type::getIntNTy(context, dest.size * 2), "rcl-zext");

    carryFlagValue = builder.CreateZExt(carryFlagValue, concatenated->getType()),"rcl-zext";
    concatenated = builder.CreateOr(concatenated, builder.CreateShl(carryFlagValue, dest.size),"rcl-or");

    countValue = builder.CreateZExt(countValue, concatenated->getType(), "rcr-zext3");
    // Define the fshl intrinsic
    llvm::Function* fshlIntrinsic = llvm::Intrinsic::getDeclaration(
        builder.GetInsertBlock()->getModule(),
        llvm::Intrinsic::fshl,
        concatenated->getType()
    );

    // Use the fshl intrinsic for the main rotation
    Value* rotated = builder.CreateCall(fshlIntrinsic, { concatenated, concatenated, builder.CreateZExtOrTrunc(countValue,concatenated->getType() ) },"rcl-fshr");

    // Extract result and new carry flag
    Value* result = builder.CreateZExtOrTrunc(rotated, destValue->getType(),"rcl-zext");
    Value* newCarryFlag = builder.CreateLShr(rotated, dest.size,"rcl-lshr");

    // Adjust the result using the original value of the carry flag
    // Set the carry flag using newCarryFlag

    auto new_flag = setFlag(context, builder, flags, FLAG_CF, SET_VALUE, newCarryFlag);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flag);
    SetOperandValue(context, builder, dest, result);
}

void lift_rcr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto count = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* countValue = GetOperandValue(context, builder, count, dest.size);

    // Get the Carry Flag (CF)

    auto flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* carryFlagValue = getFlag(context, builder, flags, FLAG_CF);

    Value* concatenated = builder.CreateZExt(destValue, Type::getIntNTy(context, dest.size * 2),"rcr-zext");
    carryFlagValue = builder.CreateZExt(carryFlagValue, concatenated->getType(),"rcr-zext2");
    concatenated = builder.CreateOr(concatenated, builder.CreateShl(carryFlagValue, dest.size),"rcr-or");

    countValue = builder.CreateZExt(countValue, concatenated->getType(), "rcr-zext3");

    // Define the fshl intrinsic
    llvm::Function* fshrIntrinsic = llvm::Intrinsic::getDeclaration(
        builder.GetInsertBlock()->getModule(),
        llvm::Intrinsic::fshl,
        concatenated->getType()
    );

    // Use the fshl intrinsic for the main rotation
    Value* rotated = builder.CreateCall(fshrIntrinsic, { concatenated, concatenated, countValue },"rcr-fshl");

    // Extract result and new carry flag
    Value* result = builder.CreateZExtOrTrunc(rotated, destValue->getType(),"rcr-zext");
    Value* newCarryFlag = builder.CreateLShr(rotated, dest.size,"rcr-lshr");

    // Adjust the result using the original value of the carry flag
    // Set the carry flag using newCarryFlag

    auto new_flag = setFlag(context, builder, flags, FLAG_CF, SET_VALUE, newCarryFlag);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flag);
    SetOperandValue(context, builder, dest, result);
}



void lift_not(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    auto Rvalue = GetOperandValue(context, builder, dest, dest.size);
    Rvalue = builder.CreateNot(Rvalue,"not-" + to_string(instruction.runtime_address) + "-");
    SetOperandValue(context, builder, dest, Rvalue);


}
void lift_setnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    // Get the current value of the ZF flag from RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // Create a check for ZF being 0 (because SETNZ sets byte to 1 if ZF = 0)
    Value* result = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Zero extend the result to byte size, since SETNZ works on bytes
    Value* byteResult = builder.CreateZExt(result, Type::getInt8Ty(context));

    // Store the result in the destination operand
    SetOperandValue(context, builder, dest, byteResult);

}
void lift_seto(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // The destination is usually a single byte in memory or a byte-sized register.
    auto dest = instruction.operands[0];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Convert the i1 (boolean) value of OF to an 8-bit integer
    Value* result = builder.CreateZExt(of, Type::getInt8Ty(context));

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}
void lift_setno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // The destination is usually a single byte in memory or a byte-sized register.
    auto dest = instruction.operands[0];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // We need to invert the value of the OF flag for SETNO.
    Value* notOf = builder.CreateNot(of, "notOF");

    // Convert the i1 (boolean) value of notOf to an 8-bit integer
    Value* result = builder.CreateZExt(notOf, Type::getInt8Ty(context));

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_setnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    // Get the current value of the CF flag from RFLAGS register
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // Check for CF being 0 (because SETNB sets byte to 1 if CF = 0)
    Value* result = builder.CreateICmpEQ(cf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Zero extend the result to byte size, since SETNB works on bytes
    Value* byteResult = builder.CreateZExt(result, Type::getInt8Ty(context));

    // Store the result in the destination operand
    SetOperandValue(context, builder, dest, byteResult);
}

void lift_setbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the CF and ZF flags
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // The condition is (CF=1 or ZF=1)
    Value* condition = builder.CreateOr(cf, zf,"setbe-or");

    // Convert condition from i1 to i8
    Value* result = builder.CreateZExt(condition, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}

void lift_setnbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the CF and ZF flags
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // The condition is (CF=0 and ZF=0)
    Value* condition = builder.CreateAnd(builder.CreateNot(cf), builder.CreateNot(zf),"setnbe-and");

    // Convert condition from i1 to i8
    Value* result = builder.CreateZExt(condition, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}


void lift_setns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    // Get the current value of the SF flag from RFLAGS register
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    // Check for SF being 0 (because SETNS sets byte to 1 if SF = 0)
    Value* result = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Zero extend the result to byte size, since SETNS works on bytes
    Value* byteResult = builder.CreateZExt(result, Type::getInt8Ty(context));

    // Store the result in the destination operand
    SetOperandValue(context, builder, dest, byteResult);
}

void lift_setp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Get the PF bit from RFLAGS register
    Value* pf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);

    // Convert PF to an 8-bit integer
    Value* result = builder.CreateZExt(pf, Type::getInt8Ty(context));

    // Assuming the first operand is the destination
    auto dest = instruction.operands[0];

    // Set the value of the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_setnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];

    // Retrieve the Parity Flag (PF) from the EFLAGS/RFLAGS register
    Value* pf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);

    // The result is 1 if PF is clear and 0 otherwise
    Value* resultValue = builder.CreateSelect(builder.CreateNot(pf),
        ConstantInt::get(Type::getInt8Ty(context), 1),
        ConstantInt::get(Type::getInt8Ty(context), 0),
        "setnp");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}


void lift_setb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // The destination is usually a single byte in memory or a byte-sized register.
    auto dest = instruction.operands[0];

    // Get the current value of the CF flag from RFLAGS register
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    // Convert the i1 (boolean) value of CF to an 8-bit integer
    Value* result = builder.CreateZExt(cf, Type::getInt8Ty(context));

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}


void lift_sets(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the SF flag
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    // Convert SF condition from i1 to i8
    Value* result = builder.CreateZExt(sf, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}


void lift_setz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the operand is the destination
    auto dest = instruction.operands[0];

    // Get the current value of the ZF flag from RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    // ZF is usually represented in LLVM as a i1 type (boolean).
    // Extend this to 8 bits to match the size of the SETZ destination.
    Value* extendedZF = builder.CreateZExt(zf, Type::getInt8Ty(context), "setz_extend");

    // Store the result to the destination operand
    SetOperandValue(context, builder, dest, extendedZF);
}

void lift_setnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    // Get the current values of the ZF, SF, and OF flags from RFLAGS register
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Check for ZF being 0
    Value* zfNotSet = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Check for SF=OF
    Value* sfEqualsOf = builder.CreateICmpEQ(sf, of);

    // Combine the two conditions with AND operation
    Value* combinedCondition = builder.CreateAnd(zfNotSet, sfEqualsOf,"setnle-and");

    // Zero extend the result to byte size, since SET instructions work on bytes
    Value* byteResult = builder.CreateZExt(combinedCondition, Type::getInt8Ty(context));

    // Store the result in the destination operand
    SetOperandValue(context, builder, dest, byteResult);
}

void lift_setle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the ZF, SF, and OF flags
    Value* zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Compute the condition (ZF=1) OR (SF != OF)
    Value* sf_ne_of = builder.CreateICmpNE(sf, of);
    Value* condition = builder.CreateOr(zf, sf_ne_of, "setle-or");

    // Convert the condition from i1 to i8
    Value* result = builder.CreateZExt(condition, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}
void lift_setnl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the SF and OF flags
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Compute the condition (SF = OF)
    Value* condition = builder.CreateICmpEQ(sf, of);

    // Convert the condition from i1 to i8
    Value* result = builder.CreateZExt(condition, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}
void lift_setl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Fetch the SF and OF flags
    Value* sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Compute the condition (SF != OF)
    Value* condition = builder.CreateICmpNE(sf, of);

    // Convert the condition from i1 to i8
    Value* result = builder.CreateZExt(condition, Type::getInt8Ty(context));

    // Set the result to the destination operand
    auto dest = instruction.operands[0];
    SetOperandValue(context, builder, dest, result);
}

void lift_neg(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    Value* Rvalue = GetOperandValue(context, builder, dest, dest.size);

    // Perform negation
    Rvalue = builder.CreateNeg(Rvalue, "neg-" + to_string(instruction.runtime_address) + "-");
    SetOperandValue(context, builder, dest, Rvalue);

    // Zero Flag (ZF)
    Value* zf = builder.CreateICmpEQ(Rvalue, ConstantInt::get(Rvalue->getType(), 0), "zf");

    // Sign Flag (SF)
    Value* sf = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0), "sf");

    // Parity Flag (PF)
    Value* pf = computeParityFlag(builder, Rvalue);

    // Update flags
    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
}


void lift_bswap(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];

    auto destValue = GetOperandValue(context, builder, dest, dest.size);

    // Define the intrinsic based on the size of the operand
    
    
    if (ConstantInt* CI = dyn_cast<ConstantInt>(destValue)) {
        // destValue is a ConstantInt
        unsigned size = destValue->getType()->getIntegerBitWidth();

        uint64_t constValue = CI->getZExtValue();
        uint64_t swappedValue = 0;

        for (unsigned i = 0; i < size; i += 8) {
            uint64_t byte_low = (constValue >> i) & 0xff;
            uint64_t byte_high = (constValue >> (size - 8 - i)) & 0xff;

            swappedValue |= (byte_high << i) | (byte_low << (size - 8 - i));
        }

        // Create a new ConstantInt with the byte-swapped value
        Value* newConstInt = ConstantInt::get(context, APInt(size, swappedValue));

        // Replace the original value with the byte-swapped value
        SetOperandValue(context, builder, dest, newConstInt);
        return;
    }

    Function* bswapIntrinsic = Intrinsic::getDeclaration(builder.GetInsertBlock()->getModule(), Intrinsic::bswap, destValue->getType() );
    // Use the intrinsic
    Value* swappedValue = builder.CreateCall(bswapIntrinsic, destValue,"bswap-" + to_string(instruction.runtime_address) + "-");
    SetOperandValue(context, builder, dest, swappedValue);



}


void lift_bt(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the bit index
    auto dest = instruction.operands[0];
    auto bitIndex = instruction.operands[1];

    // Retrieve the values
    auto destValue = GetOperandValue(context, builder, dest, dest.size);
    auto bitIndexValue = GetOperandValue(context, builder, bitIndex, dest.size);

    auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), destValue->getType()->getIntegerBitWidth()));

    // Create a mask to test the bit
    auto mask = builder.CreateShl(ConstantInt::get(destValue->getType(), 1), adjustedBitIndexValue);


    // Test the bit by performing bitwise AND
    auto testValue = builder.CreateAnd(destValue, mask,"bt");

    // Check if the bit is set. This will be a non-zero value if the bit was set.
    auto isBitSet = builder.CreateICmpNE(testValue, ConstantInt::get(destValue->getType(), 0),"btisbitset");

}

void lift_bsf(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get value for source operand
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Check if source is zero and set the zero flag accordingly
    Value* isZero = builder.CreateICmpEQ(srcValue, ConstantInt::get(srcValue->getType(), 0));
    setFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF, SET_VALUE, isZero);

    // Use the cttz (count trailing zeros) intrinsic to implement BSF
    Function* cttzIntrinsic = Intrinsic::getDeclaration(
        builder.GetInsertBlock()->getModule(),
        Intrinsic::cttz,
        srcValue->getType()
    );

    // Call the cttz intrinsic
    Value* result = builder.CreateCall(cttzIntrinsic, { srcValue, ConstantInt::get(Type::getInt1Ty(context), 0) });

    // Store the result in the destination operand
    SetOperandValue(context, builder, dest, result);
}
void lift_btr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the bit index
    auto dest = instruction.operands[0];
    auto bitIndex = instruction.operands[1];

    // Retrieve the values
    auto destValue = GetOperandValue(context, builder, dest, dest.size);
    auto bitIndexValue = GetOperandValue(context, builder, bitIndex, bitIndex.size);

    // Calculate the modulo of the bit index
    auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), destValue->getType()->getIntegerBitWidth()), "btr-urem");

    adjustedBitIndexValue = builder.CreateZExtOrTrunc(adjustedBitIndexValue, destValue->getType(), "castedBitIndex");

    // Create a mask to test the bit

    // Create a mask to clear the bit
    auto mask = builder.CreateShl(ConstantInt::get(destValue->getType(), 1), adjustedBitIndexValue, "btr-mask");
    mask = builder.CreateNot(mask, "btr-not");

    // Clear the bit
    auto resultValue = builder.CreateAnd(destValue, mask, "btr-clear-"+ to_string(instruction.runtime_address) + "-");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}


void lift_bsr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the value for the source operand
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Define the intrinsic for counting leading zeros
    Function* ctlzIntrinsic = Intrinsic::getDeclaration(
        builder.GetInsertBlock()->getModule(),
        Intrinsic::ctlz,
        srcValue->getType()
    );

    // Call the intrinsic to count leading zeros
    Value* leadingZeros = builder.CreateCall(ctlzIntrinsic, { srcValue, ConstantInt::getFalse(context) });

    // Calculate the index of the highest set bit
    Value* bitPosition = builder.CreateSub(
        ConstantInt::get(srcValue->getType(), src.size * 8 - 1),
        leadingZeros
    );

    // Set the result into the destination operand
    SetOperandValue(context, builder, dest, bitPosition);
}

void lift_btc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the bit index
    auto dest = instruction.operands[0];
    auto bitIndex = instruction.operands[1];

    // Retrieve the values
    auto destValue = GetOperandValue(context, builder, dest, dest.size);
    auto bitIndexValue = GetOperandValue(context, builder, bitIndex, bitIndex.size);

    // Calculate the modulo of the bit index
    auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), destValue->getType()->getIntegerBitWidth()));

    adjustedBitIndexValue = builder.CreateZExtOrTrunc(adjustedBitIndexValue, destValue->getType(), "castedBitIndex");

    // Create a mask to test the bit
    auto mask = builder.CreateShl(ConstantInt::get(destValue->getType(), 1), adjustedBitIndexValue, "btc-mask");

    // Test the bit by performing bitwise AND
    auto testValue = builder.CreateAnd(destValue, mask, "btc-and");
    auto isBitSet = builder.CreateICmpNE(testValue, ConstantInt::get(destValue->getType(), 0));

    // Toggle the bit by using XOR
    auto resultValue = builder.CreateXor(destValue, mask, "btc-xor");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);

    // Decide how to handle isBitSet, which indicates the original state of the bit.
    // As with the BT opcode, you might:
    // 1. Store it in a global variable representing the CF flag.
    // 2. Handle it in some other way based on your lifting design.

    // Placeholder: 
    // StoreBitInFlag(isBitSet); // you'd have to implement StoreBitInFlag
}

void lift_sar(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto count = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* countValue = GetOperandValue(context, builder, count, dest.size);

    unsigned bitWidth = destValue->getType()->getIntegerBitWidth();

    // Clamp countValue to ensure it's within the bit width of destValue
    Value* clampedCount = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth), "sar-clampedCount");

    // Perform the arithmetic right shift
    Value* shiftedValue = builder.CreateAShr(destValue, clampedCount, "sar-ashr-" + to_string(instruction.runtime_address) + "-");

    // Update EFLAGS/RFLAGS based on the result if needed. 
    Value* sf = builder.CreateICmpSLT(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0), "sf-sar");
    Value* zf = builder.CreateICmpEQ(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0), "zf-sar");
    Value* pf = computeParityFlag(builder, shiftedValue);
    Value* of = ConstantInt::get(Type::getInt64Ty(context), 0, "of-sar"); // OF is cleared

    // Compute CF: Check if clampedCount is not zero and extract the last bit shifted out
    Value* nonZeroShift = builder.CreateICmpNE(clampedCount, ConstantInt::get(clampedCount->getType(), 0), "nonZeroShift");
    Value* lastBitMask = builder.CreateShl(ConstantInt::get(destValue->getType(), 1), builder.CreateSub(clampedCount, ConstantInt::get(clampedCount->getType(), 1)), "lastBitMask");
    Value* lastBitShiftedOut = builder.CreateAnd(destValue, lastBitMask, "lastBitShiftedOut");
    Value* cf = builder.CreateSelect(nonZeroShift, builder.CreateICmpNE(lastBitShiftedOut, ConstantInt::get(lastBitShiftedOut->getType(), 0), "cf-sar"), ConstantInt::get(nonZeroShift->getType(), 0), "cf-sar2-");

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);
    new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

    SetOperandValue(context, builder, dest, shiftedValue);
}


void lift_mov(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    

    auto Rvalue = GetOperandValue(context,builder,src, src.size);


    if ((dest.type == ZYDIS_OPERAND_TYPE_MEMORY) && (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) && (src.size < dest.size)) {
        Rvalue = GetOperandValue(context, builder, src, dest.size);
#ifdef _DEVELOPMENT
        cout << " rvalue: ";  Rvalue->print(outs()); cout << " size: " << dec << src.size << " size2: " << dest.size << "\n";
#endif
    }

    switch (instruction.info.mnemonic) {
    case ZYDIS_MNEMONIC_MOVSX: {
        Rvalue = builder.CreateSExt(Rvalue, getIntSize(dest.size, context), "movsx-" + to_string(instruction.runtime_address) + "-");
        break;
    }
    case ZYDIS_MNEMONIC_MOVZX: {
        Rvalue = builder.CreateZExt(Rvalue, getIntSize(dest.size, context), "movzx-" + to_string(instruction.runtime_address) + "-");
        break;
    }
    case ZYDIS_MNEMONIC_MOVSXD: {
        Rvalue = builder.CreateSExt(Rvalue, getIntSize(dest.size, context), "movsxd-" + to_string(instruction.runtime_address) + "-");
        break;
    }
    }
    SetOperandValue(context, builder, dest, Rvalue);


}




void lift_cmovo(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If OF is set, use srcValue, otherwise keep destValue
    Value* result = builder.CreateSelect(of, srcValue, destValue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}
void lift_cmovno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    // Negate the condition since we want the opposite of OF
    of = builder.CreateNot(of, "negateOF");

    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If OF is not set (after negation), use srcValue, otherwise keep destValue
    Value* result = builder.CreateSelect(of, srcValue, destValue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}



void lift_cmovp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the PF flag from RFLAGS register
    Value* pf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);


    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If PF is not set (after negation), use srcValue, otherwise keep destValue
    Value* result = builder.CreateSelect(pf, srcValue, destValue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the PF flag from RFLAGS register
    Value* pf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);

    // Negate the PF flag since we are interested in the not parity condition
    pf = builder.CreateNot(pf, "negatePF");

    // Get values for source and destination operands
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If PF is not set (after negation), use srcValue, otherwise keep destValue
    Value* result = builder.CreateSelect(pf, srcValue, destValue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_xchg(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    auto Rvalue = GetOperandValue(context, builder, src, src.size);
    auto Lvalue = GetOperandValue(context, builder, dest, dest.size);

    SetOperandValue(context, builder, dest, Rvalue);
    SetOperandValue(context, builder, src, Lvalue);


}


void lift_lahf(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {


    auto flags = GetRegisterValue(context,builder,ZYDIS_REGISTER_RFLAGS);
    auto sf = getFlag(context, builder, flags,FLAG_SF);
    auto zf = getFlag(context, builder, flags,FLAG_ZF);
    auto af = getFlag(context, builder, flags,FLAG_AF);
    auto pf = getFlag(context, builder, flags,FLAG_PF);
    auto cf = getFlag(context, builder, flags,FLAG_CF);
    auto type16 = Type::getInt16Ty(context);

    sf = builder.CreateSExt(sf, type16);
    zf = builder.CreateSExt(sf, type16);
    af = builder.CreateSExt(sf, type16);
    pf = builder.CreateSExt(sf, type16);
    cf = builder.CreateSExt(sf, type16);

    Value* Rvalue = builder.CreateOr(
        builder.CreateShl(sf, 7),
        builder.CreateOr(
            builder.CreateShl(zf, 6),
            builder.CreateOr(
                builder.CreateShl(af, 4),
                builder.CreateOr(
                    builder.CreateShl(pf, 2), cf,"lahf-or-3-"), "lahf-or-2-"), "lahf-or1-"), "lahf-or-");


    SetRegisterValue(context, builder, ZYDIS_REGISTER_AH, Rvalue);


}

void lift_stc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {


    auto flags = GetRegisterValue(context,builder,ZYDIS_REGISTER_RFLAGS);

    auto Rvalue = builder.CreateAnd(flags, ConstantInt::get(flags->getType(), 1),"stc-and");


    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, Rvalue);


}

void lift_cmc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

    // Get the CF bit
    Value* cf = getFlag(context, builder, eflags, FLAG_CF);

    // Toggle the CF bit (complement)
    Value* toggledCF = builder.CreateXor(cf, ConstantInt::get(cf->getType(), 1),"cmd-xor");

    // Set the toggled value back into the EFLAGS/RFLAGS register
    Value* updatedEflags = setFlag(context, builder, eflags, FLAG_CF, SET_VALUE, toggledCF);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit


}
void lift_clc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

    // Clear the CF bit
    Value* clearedCF = ConstantInt::get(Type::getInt1Ty(context), 0);

    // Set the cleared CF value into the EFLAGS/RFLAGS register
    Value* updatedEflags = setFlag(context, builder, eflags, FLAG_CF, SET_VALUE, clearedCF);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

}

void lift_cld(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_EFLAGS for 32-bit

    // Clear the DF bit
    Value* clearedDF = ConstantInt::get(Type::getInt1Ty(context), 0);

    // Set the cleared value back into the EFLAGS/RFLAGS register
    Value* updatedEflags = setFlag(context, builder, eflags, FLAG_DF, SET_VALUE, clearedDF);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_EFLAGS for 32-bit
}


void lift_cli(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

    // Get the CF bit
    Value* intf = getFlag(context, builder, eflags, FLAG_IF);

    // Toggle the CF bit (complement)
    Value* resetIF = builder.CreateAnd(intf, ConstantInt::get(intf->getType(), 1),"cliand");

    // Set the toggled value back into the EFLAGS/RFLAGS register
    Value* updatedEflags = setFlag(context, builder, eflags, FLAG_IF, SET_VALUE, resetIF);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit


}
void lift_bts(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto base = instruction.operands[0];
    auto offset = instruction.operands[1];

    // Convert the offset into a bit offset
    unsigned baseBitWidth = base.size; // assuming base.size is in bytes

    // Convert the offset into a bit offset
    Value* bitOffset = GetOperandValue(context, builder, offset, offset.size);

    // Mask bitOffset to prevent undefined behavior due to shifting with too large values
    Value* bitOffsetMasked = builder.CreateAnd(bitOffset, ConstantInt::get(bitOffset->getType(), baseBitWidth - 1), "bitOffsetMasked");

    // Extract the bit from the base operand
    Value* baseVal = GetOperandValue(context, builder, base, base.size);
    Value* bit = builder.CreateLShr(baseVal, bitOffsetMasked, "bts-lshr-" + to_string(instruction.runtime_address) + "-");
    bit = builder.CreateAnd(bit, 1, "bts-and");

    // Set the CF in EFLAGS/RFLAGS based on the extracted bit
    Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    eflags = setFlag(context, builder, eflags, FLAG_CF, SET_VALUE, bit);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, eflags);

    // Set the bit in the base operand
    Value* mask = builder.CreateShl(ConstantInt::get(baseVal->getType(), 1), bitOffsetMasked, "bts-shl");
    baseVal = builder.CreateOr(baseVal, mask, "bts-or-" + to_string(instruction.runtime_address) + "-");
    SetOperandValue(context, builder, base, baseVal);
}

void lift_rdtsc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Use LLVM's timing functions to get a timestamp
    Function* clockFunc = Intrinsic::getDeclaration(builder.GetInsertBlock()->getModule(), Intrinsic::readcyclecounter);

    // Call the timing function
    Value* timestamp = builder.CreateCall(clockFunc);

    // Split the 64-bit timestamp into two 32-bit values (RDX:RAX)
    Value* rax = builder.CreateTrunc(timestamp, Type::getInt32Ty(context));
    Value* rdx = builder.CreateLShr(timestamp, 32);
    rdx = builder.CreateTrunc(rdx, Type::getInt32Ty(context));

    // Update the RAX and RDX registers with the computed values
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RAX, rax);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RDX, rdx);
}

void lift_rdtscp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Use LLVM's timing functions to get a timestamp
    Function* clockFunc = Intrinsic::getDeclaration(builder.GetInsertBlock()->getModule(), Intrinsic::readcyclecounter);

    // Call the timing function
    Value* timestamp = builder.CreateCall(clockFunc);

    // Split the 64-bit timestamp into two 32-bit values (RDX:RAX)
    Value* rax = builder.CreateTrunc(timestamp, Type::getInt32Ty(context));
    Value* rdx = builder.CreateLShr(timestamp, 32);
    rdx = builder.CreateTrunc(rdx, Type::getInt32Ty(context));

    // Simulate the retrieval of the current core ID for RCX
    // This is platform-specific and may not be directly possible in LLVM
    // For simulation, we can set a default value (e.g., 0)
    Value* rcx = ConstantInt::get(Type::getInt32Ty(context), 0);

    // Update the RAX, RDX, and RCX registers with the computed values
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RAX, rax);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RDX, rdx);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RCX, rcx);
}


void lift_cwd(LLVMContext& context, IRBuilder<>& builder) {
    // Get the AX register value
    Value* ax = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AX), Type::getInt16Ty(context));

    // Right shift by 15 to isolate the sign bit of AX
    Value* signBit = builder.CreateAShr(ax, ConstantInt::get(Type::getInt16Ty(context), 15), "getSignBit");

    // If AX was positive or zero, signBit is now 0; if negative, signBit is now 1.
    // Use signBit to set DX to either 0x0000 (for 0) or 0xFFFF (for 1).
    Value* dx = builder.CreateSelect(
        builder.CreateICmpEQ(signBit, ConstantInt::get(Type::getInt16Ty(context), 0)),
        ConstantInt::get(Type::getInt16Ty(context), 0),
        ConstantInt::get(Type::getInt16Ty(context), 0xFFFF),
        "setDX");

    // Store the result back to DX
    SetRegisterValue(context, builder, ZYDIS_REGISTER_DX, dx);
}
void lift_cqo(LLVMContext& context, IRBuilder<>& builder) {
    // Retrieve the RAX register's value
    Value* rax = GetRegisterValue(context, builder, ZYDIS_REGISTER_RAX);
    rax = builder.CreateSExtOrTrunc(rax, Type::getInt64Ty(context));
    // Extract the sign bit (MSB) of RAX
    Value* msb = builder.CreateLShr(rax, 63,"cqo-msb");  // 63 for a 64-bit register
    msb = builder.CreateAnd(msb, 1,"cqo-and");

    // If the MSB is 1, RDX will be all 1's, otherwise, all 0's.
    // This can be achieved by sign extending the MSB to 64 bits.
    Value* rdx = builder.CreateSExt(msb, Type::getInt64Ty(context));

    // Update the RDX register with the computed value
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RDX, rdx);
}


void lift_cbw(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming you have a method to get the AL register value
    Value* al = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AL), Type::getInt8Ty(context) );

    // Sign extend AL to 16 bits (i.e., AX's size)
    Value* ax = builder.CreateSExt(al, Type::getInt16Ty(context),"cbw");

    // Store the result back to AX
    SetRegisterValue(context, builder, ZYDIS_REGISTER_AX, ax);
}

void lift_cwde(LLVMContext& context, IRBuilder<>& builder) {
    // Get the AX register value
    Value* ax = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AX), Type::getInt16Ty(context) );

    // Sign extend AX to 32 bits (i.e., EAX's size)
    Value* eax = builder.CreateSExt(ax, Type::getInt32Ty(context),"cwde");

    // Store the result back to EAX
    SetRegisterValue(context, builder, ZYDIS_REGISTER_EAX, eax);
}

void lift_stosd(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming 32-bit mode for simplicity. Adjust for 16-bit or 64-bit as necessary.

    // Step 1: Retrieve the value in EAX
    Value* eaxValue = GetRegisterValue(context, builder, ZYDIS_REGISTER_EAX);

    // Step 2: Retrieve the current value of EDI
    Value* ediValue = GetRegisterValue(context, builder, ZYDIS_REGISTER_EDI);

    // Step 3: Store the value from EAX into the memory pointed by EDI
    builder.CreateStore(eaxValue, builder.CreateIntToPtr(ediValue, PointerType::get(IntegerType::get(context, 32), 0)));

    // Step 4: Update EDI based on the direction flag
    Value* dfValue = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_DF); // Implement GetFlagValue to retrieve the direction flag
    Value* increment = ConstantInt::get(Type::getInt32Ty(context), 4); // 4 bytes for a doubleword
    Value* updatedEdiValue = builder.CreateSelect(dfValue, builder.CreateSub(ediValue, increment), builder.CreateAdd(ediValue, increment));

    // Step 5: Set the updated EDI value
    SetRegisterValue(context, builder, ZYDIS_REGISTER_EDI, updatedEdiValue);

    // Flags are not affected by STOSD
}


void lift_cdqe(LLVMContext& context, IRBuilder<>& builder) {
    // Get the EAX register value
    Value* eax = builder.CreateZExtOrTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_EAX), Type::getInt32Ty(context) , "cdqe-trunc");

    // Sign extend EAX to 64 bits (i.e., RAX's size)
    Value* rax = builder.CreateSExt(eax, Type::getInt64Ty(context),"cdqe");

    // Store the result back to RAX
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RAX, rax);
}
void lift_shl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto count = instruction.operands[1];
    
    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* countValue = GetOperandValue(context, builder, count, dest.size);

    auto destBitWidth = destValue->getType()->getIntegerBitWidth();
    auto modShiftValue = ConstantInt::get(countValue->getType(), destBitWidth);
    auto effectiveCountValue = builder.CreateURem(countValue, modShiftValue);

    // Perform the logical left shift
    Value* shiftedValue = builder.CreateShl(destValue, effectiveCountValue, "shl-shift-" + to_string(instruction.runtime_address) + "-");

    // Update EFLAGS/RFLAGS based on the result if needed.
    Value* sf = builder.CreateICmpSLT(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0), "sf");
    Value* zf = builder.CreateICmpEQ(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0), "zf");
    Value* pf = computeParityFlag(builder, shiftedValue);

    // Compute CF: get the Nth (n = count) bit
    // ( r>>16-n ) & 0xff
    auto p1 = builder.CreateSub(modShiftValue, effectiveCountValue);
    auto p2 = builder.CreateLShr(destValue, p1);

    Value* cf = builder.CreateTrunc(p2,Type::getInt1Ty(context) );
    

    // Compute OF: OF is set to the most-significant bit of the result for the first shift, otherwise unchanged
// Compute OF: OF is set to the most-significant bit of the result for the first shift, otherwise unchanged
    Value* msbOfResult = builder.CreateLShr(shiftedValue, ConstantInt::get(shiftedValue->getType(), destBitWidth - 1));
    msbOfResult = builder.CreateTrunc(msbOfResult, Type::getInt1Ty(context));  // Truncate to i1
    Value* isOneShift = builder.CreateICmpEQ(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
    Value* currentOF = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);
    Value* of = builder.CreateSelect(isOneShift, msbOfResult, currentOF, "of-shl");


    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

    SetOperandValue(context, builder, dest, shiftedValue);

}


void lift_shld(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto source = instruction.operands[1];
    auto count = instruction.operands[2];

    auto destValue = GetOperandValue(context, builder, dest, dest.size);
    auto sourceValue = GetOperandValue(context, builder, source, dest.size);
    auto countValue = GetOperandValue(context, builder, count, dest.size);

    // Calculate effective shift count (modulo the bit width of destValue)
    unsigned bitWidth = destValue->getType()->getIntegerBitWidth();
    auto effectiveCountValue = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth-1), "effectiveShiftCount");

    // Shift the destination value to the left
    auto shiftedDest = builder.CreateShl(destValue, effectiveCountValue, "shiftedDest");

    // Calculate the complement of the effective shift count
    auto complementCount = builder.CreateSub(ConstantInt::get(effectiveCountValue->getType(), bitWidth-1), effectiveCountValue, "complementCount");

    // Shift the source value to the right by complementCount
    auto shiftedSource = builder.CreateLShr(sourceValue, complementCount, "shiftedSource");

    // Combine shiftedDest and shiftedSource
    auto resultValue = builder.CreateOr(shiftedDest, shiftedSource, "shldResult-" + to_string(instruction.runtime_address) + "-");


    // Update EFLAGS/RFLAGS based on the result
    Value* sf = builder.CreateICmpSLT(resultValue, ConstantInt::get(resultValue->getType(), 0), "sf");
    Value* zf = builder.CreateICmpEQ(resultValue, ConstantInt::get(resultValue->getType(), 0), "zf");
    Value* pf = computeParityFlag(builder, resultValue);

    // Calculate CF and OF
    // TODO

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);
    //new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    //new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);


    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}

void lift_shrd(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto source = instruction.operands[1];
    auto count = instruction.operands[2];

    auto destValue = GetOperandValue(context, builder, dest, dest.size);
    auto sourceValue = GetOperandValue(context, builder, source, dest.size);
    auto countValue = GetOperandValue(context, builder, count, dest.size);

    // Calculate effective shift count (modulo the bit width of destValue)
    unsigned bitWidth = destValue->getType()->getIntegerBitWidth();
    auto effectiveCountValue = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth -1 ), "effectiveShiftCount");

    // Shift the destination value to the right
    auto shiftedDest = builder.CreateLShr(destValue, effectiveCountValue, "shiftedDest");

    // Calculate the complement of the effective shift count
    auto complementCount = builder.CreateSub(ConstantInt::get(effectiveCountValue->getType(), bitWidth - 1), effectiveCountValue, "complementCount");

    // Shift the source value to the left by complementCount
    auto shiftedSource = builder.CreateShl(sourceValue, complementCount, "shiftedSource");

    // Combine shiftedDest and shiftedSource
    auto resultValue = builder.CreateOr(shiftedDest, shiftedSource, "shrdResult-" + to_string(instruction.runtime_address) + "-");

    auto shiftCount = builder.CreateSub(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1), "shiftCount");

    // Ensure shift count is not negative
    auto zero = ConstantInt::get(effectiveCountValue->getType(), 0);
    auto isNonNegative = builder.CreateICmpSGE(shiftCount, zero, "isNonNegative");
    auto validShiftCount = builder.CreateSelect(isNonNegative, shiftCount, zero, "validShiftCount");

    Value* shiftedValue = builder.CreateLShr(destValue, validShiftCount, "shiftedValue");
    Value* cf = builder.CreateAnd(shiftedValue, ConstantInt::get(destValue->getType(), 1), "cf-shrd");


    Value* of = builder.CreateXor(builder.CreateLShr(resultValue, bitWidth - 1,"of1"), builder.CreateLShr(resultValue, bitWidth - 2));
    Value* sf = builder.CreateICmpSLT(resultValue, ConstantInt::get(resultValue->getType(), 0));
    Value* zf = builder.CreateICmpEQ(resultValue, ConstantInt::get(resultValue->getType(), 0));
    Value* pf = computeParityFlag(builder, resultValue);

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

}


void lift_shr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto count = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* countValue = GetOperandValue(context, builder, count, dest.size);

    auto destBitWidth = destValue->getType()->getIntegerBitWidth();
    auto modShiftValue = ConstantInt::get(countValue->getType(), destBitWidth);
    auto effectiveCountValue = builder.CreateURem(countValue, modShiftValue);

    // Perform the logical left shift
    Value* shiftedValue = builder.CreateLShr(destValue, effectiveCountValue, "shr-shift-" + to_string(instruction.runtime_address) + "-");

    // Optionally, update EFLAGS/RFLAGS based on the result if needed. 
    // For instance, setting CF and OF flags based on the SHL result.
    // ...

    Value* cf = builder.CreateAnd(builder.CreateLShr(destValue, builder.CreateSub(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1))), ConstantInt::get(destValue->getType(), 1));
    unsigned bitWidth = destValue->getType()->getIntegerBitWidth();

    // Compare 'countValue' to 1
    Value* isOneBitShift = builder.CreateICmpEQ(countValue, ConstantInt::get(countValue->getType(), 1));

    // Calculate OF for a 1-bit shift
    Value* ofForOneBitShift = builder.CreateLShr(destValue, bitWidth - 1);

    // Handle OF based on the shift count
    // If countValue is 1, use 'ofForOneBitShift', else OF is undefined (or you can set it to a default value)
    Value* of = builder.CreateSelect(isOneBitShift, ofForOneBitShift, ConstantInt::get(countValue->getType(), 0));

    Value* sf = builder.CreateICmpSLT(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0));
    Value* zf = builder.CreateICmpEQ(shiftedValue, ConstantInt::get(shiftedValue->getType(), 0));
    Value* pf = computeParityFlag(builder, shiftedValue);


    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

    SetOperandValue(context, builder, dest, shiftedValue);

}





// for now assume every call is fake
void lift_call(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {
    
    // 0 = function
    // 1 = rip
    // 2 = register rsp
    // 3 = [rsp]
    auto src = instruction.operands[0]; // value that we are pushing
    auto rsp = instruction.operands[2]; // value that we are pushing
    auto rsp_memory = instruction.operands[3]; // value that we are pushing

    auto RspValue = GetOperandValue(context, builder, rsp, rsp.size);

    auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
    auto result = builder.CreateSub(RspValue, val, "calling_newrsp-" + to_string(instruction.runtime_address) + "-");

    SetOperandValue(context, builder, rsp, result); // sub rsp 8 first,

    auto push_into_rsp = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    Value* pushing = SetOperandValue(context, builder, rsp_memory, push_into_rsp); // push [rsp] into stack



    string block_name = "jmp-call";
    auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());


    builder.CreateBr(bb);

    uintptr_t test = src.imm.value.s + instruction.runtime_address;
    //cout << "jmp address: " << test << "\n";
    blockAddresses->push_back(make_tuple(test, bb, getRegisterList()));

}

int ret_count = 0;
void lift_ret(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {
    // [0] = rip
    // [1] = rsp
    // [2] = [rsp]

    // if its ret 0x10
    // then its
    // [0] = 0x10
    // [1] = rip
    // [2] = rsp
    // [3] = [rsp]

    auto rspaddr = instruction.operands[2];

    auto rsp = ZYDIS_REGISTER_RSP;
    auto rspvalue = GetRegisterValue(context, builder, rsp);
    if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        rspaddr = instruction.operands[3];
    }

    auto realval = GetOperandValue(context,builder, rspaddr, rspaddr.size);


    auto block = builder.GetInsertBlock();
    block->setName("ret_check" + to_string(ret_count));
    auto function = block->getParent();

    auto lastinst = builder.CreateRet(realval);
#ifdef _DEVELOPMENT
    cout << "rspvalue: "; rspvalue->print(outs()); cout << "\n";
    std::string Filename = "output_rets.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName() );


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "ret_check" + to_string(ret_count))
            clonedBlock = &blocks;
    }


    uintptr_t destination;
#ifdef _DEVELOPMENT
    std::string Filename_before = "output_before_rop_opt.ll";
    std::error_code EC_before;
    llvm::raw_fd_ostream OS_before(Filename_before, EC_before);
    clonedFunc->print(OS_before);
#endif
    ROP_info ROP = isROP(clonedFunc, *clonedBlock, destination);
    


#ifdef _DEVELOPMENT
    std::string Filename_after = "output_after_rop_opt.ll";
    std::error_code EC_after;
    llvm::raw_fd_ostream OS_after(Filename_after, EC_after);
    clonedFunc->print(OS_after);
#endif
    clonedFunc->eraseFromParent();
    lastinst->eraseFromParent();

    block->setName("previousret_block");

    //cout << "rop value: " << ROP << "\n";
    if (ROP == ROP_return) {
        // can we make it so we remove the store for it?
        
        
        //cout << "jmp address: " << destination << "\n";


        block->setName("fake_ret");

        string block_name = "jmp_ret-" + to_string(destination) + "-";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
        auto result = builder.CreateAdd(rspvalue, val, "ret-new-rsp-" + to_string(instruction.runtime_address) + "-");

        if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            rspaddr = instruction.operands[3];
            auto offset = instruction.operands[0];
            result = builder.CreateSub(rspvalue, ConstantInt::get(rspvalue->getType(), offset.imm.value.u));


        }

        SetRegisterValue(context, builder, rsp, result); // then add rsp 8


        builder.CreateBr(bb);

        blockAddresses->push_back(make_tuple(destination, bb, getRegisterList()));
        (*run) = 0;
    }
    else if (ROP == REAL_return) {

        block->setName("real_ret");
        builder.CreateRet(GetRegisterValue(context,builder,ZYDIS_REGISTER_RAX) );
        Function* originalFunc_finalnopt = builder.GetInsertBlock()->getParent();
#ifdef _DEVELOPMENT
        std::string Filename_finalnopt = "output_finalnoopt.ll";
        std::error_code EC_finalnopt;
        llvm::raw_fd_ostream OS_finalnopt(Filename_finalnopt, EC_finalnopt);
        
        originalFunc_finalnopt->print(OS_finalnopt);
#endif

        llvm::ValueToValueMapTy VMap_finale;
        //function->print(outs());
        llvm::Function* clonedFunc_finale = llvm::CloneFunction(originalFunc_finalnopt, VMap_finale);

        final_optpass(originalFunc_finalnopt);
#ifdef _DEVELOPMENT
        std::string Filename = "output_finalopt.ll";
        std::error_code EC;
        llvm::raw_fd_ostream OS(Filename, EC);
        originalFunc_finalnopt->print(OS);
#endif
        clonedFunc_finale->eraseFromParent();
        (*run) = 0;
    }



}

void lift_jmp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {

    auto dest = instruction.operands[0];
    
    auto Value = GetOperandValue(context,builder,dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto newRip = builder.CreateAdd(Value, ripval, "jump-xd-" + to_string(instruction.runtime_address) + "-");
    
 
    if (dest.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        auto rspvalue = GetOperandValue(context, builder, dest, 64);
        auto trunc = builder.CreateZExtOrTrunc(rspvalue, llvm::Type::getInt64Ty(context), "jmp-register");


        auto block = builder.GetInsertBlock();
        block->setName("jmp_check" + to_string(ret_count));
        auto function = block->getParent();

        auto lastinst = builder.CreateRet(trunc);

        llvm::ValueToValueMapTy VMap;
        #ifdef _DEVELOPMENT
        std::string Filename = "output_beforeJMP.ll";
        std::error_code EC;
        llvm::raw_fd_ostream OS(Filename, EC);
        function->print(OS);
        #endif
        llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
        std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
        clonedFunctmp->removeFromParent();

        // Add the cloned function to the destination module
        destinationModule->getFunctionList().push_back(clonedFunctmp);

        Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());



        BasicBlock* clonedBlock = block;
        for (auto& blocks : *clonedFunc) {
            if (blocks.getName() == "jmp_check" + to_string(ret_count))
                clonedBlock = &blocks;
        }

        uintptr_t destination;
        JMP_info ROP = isJOP(clonedFunc, *clonedBlock, destination);

#ifdef _DEVELOPMENT
        std::string Filename2 = "output_afterJMP.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        clonedFunc->print(OS2);
#endif

        llvm::ValueToValueMapTy VMap_test;

        lastinst->eraseFromParent();

        block->setName("previousjmp_block");
        //cout << "isJOP:" << ROP << "\n";
        if (ROP == JOP_jmp) {

            string block_name = "jmp-" + to_string(destination) + "-";
            auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

            builder.CreateBr(bb);

            blockAddresses->push_back(make_tuple(destination, bb, getRegisterList()));
            (*run) = 0;
        }
        clonedFunc->eraseFromParent();
        (*run) = 0;
        //if ROP is not JOP_jmp, then its bugged
        return;
    }
    

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, newRip);

    uintptr_t test = dest.imm.value.s + instruction.runtime_address ;
    //cout << "jmp address: " << test << "\n";

    string block_name = "jmp-" + to_string(test) + "-";
    auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

    builder.CreateBr(bb);

    blockAddresses->push_back( make_tuple(test, bb,  getRegisterList() ) );
    (*run) = 0;

}

void branchHelper(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, opaque_info opaque, Value* condition, Value* newRip, string instname) {

    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto result = newRip;
    auto dest = instruction.operands[0];
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = instname+"-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = instname+"-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {
        DebugBreak();
        string block_name = instname+"-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = instname+"-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());


        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(condition, newRip, ripval);
        builder.CreateCondBr(condition, bb, bb2);

        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }

}


int jnz_count = 0;
// jnz and jne
void lift_jnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto zf = getFlag(context, builder, GetRegisterValue(context,builder,ZYDIS_REGISTER_RFLAGS), FLAG_ZF );

    auto dest = instruction.operands[0];
    
    auto Value = GetOperandValue(context,builder,dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jnz");

    
    zf = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));


    auto block = builder.GetInsertBlock();
    block->setName("jnz_check" + to_string(jnz_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(zf, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jnz_check" + to_string(jnz_count))
            clonedBlock = &blocks;
    }

    #ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
    #endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjnz_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0


    branchHelper(context, builder, instruction, blockAddresses, opaque, zf, newRip, "jnz");


    jnz_count++;


}

int jnb_count = 0;
// jnz and jne
void lift_jnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jnb");


    cf = builder.CreateICmpEQ(cf, ConstantInt::get(Type::getInt1Ty(context), 0));


    auto block = builder.GetInsertBlock();
    block->setName("jnb_check" + to_string(jnb_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(cf, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jnb_check" + to_string(jnb_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjnb_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0


    branchHelper(context, builder, instruction, blockAddresses, opaque, cf, newRip, "jnb");


    jnb_count++;


}

int jb_count = 0;
// jnz and jne
void lift_jb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jb");




    auto block = builder.GetInsertBlock();
    block->setName("jb_check" + to_string(jnb_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(cf, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jb_check" + to_string(jnb_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjb_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0


    branchHelper(context, builder, instruction, blockAddresses, opaque, cf, newRip, "jb");


    jb_count++;


}


int jp_count = 0;
// jnz and jne
void lift_jp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto condition = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jp");




    auto block = builder.GetInsertBlock();
    block->setName("jp_check" + to_string(jp_count));
    auto function = block->getParent();
    auto newcond = builder.CreateZExt(condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jp_check" + to_string(jp_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjp_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0


    branchHelper(context, builder, instruction, blockAddresses, opaque, condition, newRip, "jp");


    jp_count++;


}

int jnp_count = 0;
// jnz and jne
void lift_jnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto condition = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_PF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jnp");




    auto block = builder.GetInsertBlock();
    block->setName("jnp_check" + to_string(jnb_count));
    auto function = block->getParent();
    condition = builder.CreateNot(condition);
    auto newcond = builder.CreateZExt(condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jnp_check" + to_string(jnp_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjnp_block-"+to_string(instruction.runtime_address) +"-");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0


    branchHelper(context, builder, instruction, blockAddresses, opaque, condition, newRip, "jnp-"+to_string(instruction.runtime_address) +"-");


    jnp_count++;


}

int jz_count = 0;
void lift_jz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jz");




    auto block = builder.GetInsertBlock();
    block->setName("jnz_check" + to_string(jz_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(zf, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jz_check" + to_string(jnz_count))
            clonedBlock = &blocks;
    }

    #ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
    #endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjnz_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0
    auto result = newRip;


    //help branch
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = "jz-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = "jz-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {

        string block_name = "jz-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = "jz-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(zf, newRip, ripval);
        builder.CreateCondBr(zf, bb, bb2);


        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }


    jz_count++;



}


auto jnle_count = 0;
void lift_jnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto newRip = builder.CreateAdd(Value, ripval, "jnle");

    // Check if neither CF nor ZF are set
    auto zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);
    auto sf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);
    auto of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);


    // ZF = 0 and SF = OF
    auto zf_zero = builder.CreateNot(zf, "zf_zero");
    auto sf_eq_of = builder.CreateICmpEQ(sf, of, "sf_eq_of");
    auto condition = builder.CreateAnd(zf_zero, sf_eq_of, "jnle_Condition");


    auto block = builder.GetInsertBlock();
    block->setName("jnle_check" + to_string(jnle_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jnle_check" + to_string(jnle_count))
            clonedBlock = &blocks;
    }
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif

#ifdef _DEVELOPMENT
    std::string Filename2 = "output_opaque_opt.ll";
    std::error_code EC2;
    llvm::raw_fd_ostream OS2(Filename2, EC2);
    clonedFunc->print(OS2);
#endif

    lastinst->eraseFromParent();
    clonedFunc->eraseFromParent();

    string opinfo = (opaque == OPAQUE_TRUE ? "True" : "False");
    block->setName("previousjnle-block_" + opinfo + "-");

    branchHelper(context, builder, instruction, blockAddresses, opaque, condition, newRip, "jnle");


    jnle_count++;
}

auto jbe_count = 0;
void lift_jbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // If CF=0 and ZF=0, then jump. Otherwise, do not jump.

    auto cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);
    auto zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto newRip = builder.CreateAdd(Value, ripval, "jbe");

    // Check if neither CF nor ZF are set
    auto condition = builder.CreateOr(cf, zf, "jbe_Condition");

    auto block = builder.GetInsertBlock();
    block->setName("jbe_check" + to_string(jbe_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jbe_check" + to_string(jbe_count))
            clonedBlock = &blocks;
    }
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);
     
#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif

#ifdef _DEVELOPMENT
    std::string Filename2 = "output_opaque_opt.ll";
    std::error_code EC2;
    llvm::raw_fd_ostream OS2(Filename2, EC2);
    clonedFunc->print(OS2);
#endif

    lastinst->eraseFromParent();
    clonedFunc->eraseFromParent();

    string opinfo = (opaque == OPAQUE_TRUE ? "True" : "False");
    block->setName("previousjbe-block_" + opinfo + "-");

    branchHelper(context, builder, instruction, blockAddresses, opaque, condition, newRip, "jbe");


    jbe_count++;
}

auto jnbe_count = 0;
// jnbe == ja
void lift_jnbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // If CF=0 and ZF=0, then jump. Otherwise, do not jump.

    auto cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);
    auto zf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_ZF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto newRip = builder.CreateAdd(Value, ripval, "jnbe");

    // Check if neither CF nor ZF are set
    auto condition = builder.CreateAnd(builder.CreateNot(cf, "notCF"), builder.CreateNot(zf, "notZF"), "jnbe_ja_Condition");

    auto block = builder.GetInsertBlock();
    block->setName("jnbe_ja_check"+to_string(jnbe_count) );
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jnbe_ja_check" + to_string(jnbe_count))
            clonedBlock = &blocks;
    }
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif


    lastinst->eraseFromParent();
    clonedFunc->eraseFromParent();

    string opinfo = (opaque == OPAQUE_TRUE ? "True" : "False");
    block->setName("previousjnbe_ja_block_" + opinfo + "-");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0

    //cout << "is Opaque: " << opaque << "\n";

    //help branch
    auto result = newRip;
    switch (opaque) {
        case OPAQUE_TRUE: {
            string block_name = "jnbe-ja-jump";
            auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

            SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
            builder.CreateBr(bb);
            blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
            break;
        }
        case OPAQUE_FALSE: {
            string block_name2 = "jnbe-ja-notjump";
            auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
            builder.CreateBr(bb2);
            result = ripval;
            SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
            blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
            result = ripval;
            break;
        }
        case NOT_OPAQUE: {

            string block_name = "jnbe-ja-jump";
            auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
            string block_name2 = "jnbe-ja-notjump";
            auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
 

            result = builder.CreateSelect(condition, newRip, ripval);

            SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

            builder.CreateCondBr(condition, bb, bb2);


            auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
            builder.SetInsertPoint(bb);

            builder.CreateRet(placeholder);

            builder.SetInsertPoint(bb2);

            builder.CreateRet(placeholder);

            blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
            blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

        }
    }


    jnbe_count++;
}



int jo_count = 0;
void lift_jo(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jo");




    auto block = builder.GetInsertBlock();
    block->setName("jo_check" + to_string(jo_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(of, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jo_check" + to_string(jo_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjo_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0
    auto result = newRip;


    //help branch
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = "jo-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = "jo-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {

        string block_name = "jo-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = "jo-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(of, newRip, ripval);
        builder.CreateCondBr(of, bb, bb2);


        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }


    jo_count++;



}

int jno_count = 0;
void lift_jno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_OF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jno");




    auto block = builder.GetInsertBlock();
    block->setName("jno_check" + to_string(jo_count));
    auto function = block->getParent();
    of = builder.CreateNot(of);
    auto newcond = builder.CreateZExt(of, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jno_check" + to_string(jo_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjno_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0
    auto result = newRip;


    //help branch
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = "jno-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = "jno-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {

        string block_name = "jno-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = "jno-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(of, newRip, ripval);
        builder.CreateCondBr(of, bb, bb2);


        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }


    jno_count++;



}

int js_count = 0;
void lift_js(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "js");




    auto block = builder.GetInsertBlock();
    block->setName("js_check" + to_string(js_count));
    auto function = block->getParent();

    auto newcond = builder.CreateZExt(of, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "js_check" + to_string(js_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjo_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0
    auto result = newRip;


    //help branch
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = "jo-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = "jo-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {

        string block_name = "js-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = "js-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(of, newRip, ripval);
        builder.CreateCondBr(of, bb, bb2);


        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }


    js_count++;



}

int jns_count = 0;
void lift_jns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

    // if 0, then jmp, if not then not jump

    auto of = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_SF);

    auto dest = instruction.operands[0];

    auto Value = GetOperandValue(context, builder, dest, 64);
    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

    auto newRip = builder.CreateAdd(Value, ripval, "jns");




    auto block = builder.GetInsertBlock();
    block->setName("jns_check" + to_string(jns_count));
    auto function = block->getParent();
    of = builder.CreateNot(of);
    auto newcond = builder.CreateZExt(of, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);

    llvm::ValueToValueMapTy VMap;
    //function->print(outs());
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", context);
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());


    BasicBlock* clonedBlock = block;
    for (auto& blocks : *clonedFunc) {
        if (blocks.getName() == "jns_check" + to_string(jns_count))
            clonedBlock = &blocks;
    }

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif
    opaque_info opaque = isOpaque(clonedFunc, *clonedBlock);

    lastinst->eraseFromParent();

    clonedFunc->eraseFromParent();
    block->setName("previousjns_block");
    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0
    auto result = newRip;


    //help branch
    switch (opaque) {
    case OPAQUE_TRUE: {
        string block_name = "jns-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {
        string block_name2 = "jns-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {

        string block_name = "jns-jump";
        auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());
        string block_name2 = "jns-notjump";
        auto bb2 = llvm::BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);

        result = builder.CreateSelect(of, newRip, ripval);
        builder.CreateCondBr(of, bb, bb2);


        auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        builder.SetInsertPoint(bb);

        builder.CreateRet(placeholder);

        builder.SetInsertPoint(bb2);

        builder.CreateRet(placeholder);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));

    }
    }


    jns_count++;



}



void lift_lea(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    auto Rvalue = GetEffectiveAddress(context,builder,src,dest.size);

    SetOperandValue(context, builder, dest, Rvalue);


}

void lift_add_sub(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto Lvalue = GetOperandValue(context, builder, dest, dest.size);

    Value* result = nullptr;

    Value* cf = nullptr; // Carry flag
    Value* of = nullptr; // Overflow flag
    switch (instruction.info.mnemonic) {
    case ZYDIS_MNEMONIC_ADD: {result = builder.CreateAdd(Lvalue, Rvalue,"realadd-" + to_string(instruction.runtime_address) + "-");  
        cf = builder.CreateICmpULT(result, Lvalue); // CF set if result < Lvalue
        of = builder.CreateXor(builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0)),
            builder.CreateICmpSLT(result, Lvalue)); // OF set if sign of Lvalue is different from sign of result
        break; }
    case ZYDIS_MNEMONIC_SUB: {result = builder.CreateSub(Lvalue, Rvalue,"realsub-" + to_string(instruction.runtime_address) + "-");  
        cf = builder.CreateICmpULT(Lvalue, Rvalue); // CF set if Lvalue < Rvalue
        of = builder.CreateXor(builder.CreateICmpSLT(Lvalue, Rvalue),
            builder.CreateICmpSLT(result, Lvalue)); // OF set if sign of Lvalue is different from sign of result
        break; }
    case ZYDIS_MNEMONIC_IMUL: {result = builder.CreateMul(Lvalue, Rvalue); break; }
    case ZYDIS_MNEMONIC_IDIV: {
        result = builder.CreateSDiv(Lvalue,Rvalue);
        auto remained = builder.CreateSRem(Lvalue,Rvalue);

        SetOperandValue(context, builder, instruction.operands[2], remained);
        break; }
    }
    SetOperandValue(context, builder, dest, result);

    Value* sf = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0)); // SF set if result is negative
    Value* zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0)); // ZF set if result is zero
    Value* pf = computeParityFlag(builder, result); // Compute PF inline or using a helper function

    // Retrieve old flags
    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

    // Set new flags
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_CF, SET_VALUE, cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    // Update flags register
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);


}

void lift_xor_and_or(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
    unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
    llvm::Value* bitWidthVal = llvm::ConstantInt::get(Lvalue->getType(), bitWidth);

    Value* result = nullptr;
    Value* of = nullptr;
    Value* cf = nullptr;
    Value* sf = nullptr;
    Value* zf = nullptr;
    Value* pf = nullptr;

    switch (instruction.info.mnemonic) {
    case ZYDIS_MNEMONIC_XOR: {result = builder.CreateXor(Lvalue, Rvalue,"xor-" + to_string(instruction.runtime_address) + "-");
        of = ConstantInt::get(Type::getInt64Ty(context), 0); // OF is cleared
        cf = ConstantInt::get(Type::getInt64Ty(context), 0); // CF is cleared
        sf = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0)); // SF
        zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0)); // ZF
        pf = computeParityFlag(builder, result); // PF
        break; }
    case ZYDIS_MNEMONIC_OR: {result = builder.CreateOr(Lvalue, Rvalue,"or-" + to_string(instruction.runtime_address) + "-");
        of = ConstantInt::get(Type::getInt64Ty(context), 0); // OF is cleared
        cf = ConstantInt::get(Type::getInt64Ty(context), 0); // CF is cleared
        sf = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0)); // SF
        zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0)); // ZF
        pf = computeParityFlag(builder, result); // PF
        break; }
    case ZYDIS_MNEMONIC_AND: {result = builder.CreateAnd(Lvalue, Rvalue,"and-" + to_string(instruction.runtime_address) + "-");
        of = ConstantInt::get(Type::getInt64Ty(context), 0); // OF is cleared
        cf = ConstantInt::get(Type::getInt64Ty(context), 0); // CF is cleared
        sf = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0)); // SF
        zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0)); // ZF
        pf = computeParityFlag(builder, result); // PF
        break; }
    case ZYDIS_MNEMONIC_ROL:
    case ZYDIS_MNEMONIC_ROR: {
        if (ConstantInt* CL = dyn_cast<ConstantInt>(Lvalue)) {
            if (ConstantInt* CR = dyn_cast<ConstantInt>(Rvalue)) {
                unsigned size = CL->getType()->getIntegerBitWidth();
                uint64_t lValue = CL->getZExtValue();
                uint64_t rValue = CR->getZExtValue() % size; // Ensure the rotation is within bounds

                uint64_t rotatedValue = 0;
                if (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROL) {
                    // Perform constant rotation left
                    rotatedValue = (lValue << rValue) | (lValue >> (size - rValue));
                }
                else {
                    // Perform constant rotation right
                    rotatedValue = (lValue >> rValue) | (lValue << (size - rValue));
                }

                // Create a new ConstantInt with the rotated value
                result = ConstantInt::get(context, APInt(size, rotatedValue));
                if (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROR) {
                    // CF for ROR: set to the MSB of the result
                    cf =
                        builder.CreateTrunc( builder.CreateLShr(result,size-1), Type::getInt1Ty(context), "ror-cf");

                    #ifdef _DEVELOPMENT
                    cout << " Lvalue: ";  Lvalue->print(outs()); cout << "\n";
                    cout << " Rvalue: ";  Rvalue->print(outs()); cout << "\n";
                    cout << " result: ";  result->print(outs()); cout << "\n";
                    cout << " cf: ";  cf->print(outs()); cout << "\n";
                    #endif
                }
                break;
            }
        }

        // If not constants, use the intrinsic functions
        llvm::Intrinsic::ID intrinsicID = (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROL) ? llvm::Intrinsic::fshl : llvm::Intrinsic::fshr;
        llvm::Function* rotateIntrinsic = llvm::Intrinsic::getDeclaration(
            builder.GetInsertBlock()->getModule(),
            intrinsicID,
            Lvalue->getType()
        );

        // Use the intrinsic for ROL or ROR
        result = builder.CreateCall(rotateIntrinsic, { Lvalue, Lvalue, Rvalue },
            (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROL ? "rol_result-" : "ror_result-") +
            std::to_string(instruction.runtime_address) + "-");

        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROL) {
            // CF for ROL: set to the MSB of the result
            cf = builder.CreateICmpEQ(
                builder.CreateAnd(result, ConstantInt::get(result->getType(), 1ULL << (bitWidth - 1))),
                ConstantInt::get(result->getType(), 1ULL << (bitWidth - 1)),
                "rol-cf"
            );

            auto msb = builder.CreateLShr(result, ConstantInt::get(result->getType(), bitWidth - 1), "rol-msb");
            auto msbAsBool = builder.CreateTrunc(msb, Type::getInt1Ty(context), "rol-msb-bool");

            of = builder.CreateXor(cf, msbAsBool, "rol-of");
        }
        else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_ROR) {
            // CF for ROR: set to the LSB of the result
            cf =
                builder.CreateTrunc(result,Type::getInt1Ty(context), "ror-cf");
        }
        break;
    }
    default: {
        break;
    }
    }


    SetOperandValue(context, builder, dest, result);
    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = old_flags;
    if (of) new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);
    if (cf) new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, cf);
    if (sf) new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, sf);
    if (zf) new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    if (pf) new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

}

void lift_inc_dec(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto operand = instruction.operands[0];

    Value* originalValue = GetOperandValue(context, builder, operand, operand.size);
    Value* one = ConstantInt::get(originalValue->getType(), 1, true);
    Value* result;

    if (instruction.info.mnemonic == ZYDIS_MNEMONIC_INC) {
        result = builder.CreateAdd(originalValue, one, "inc-" + to_string(instruction.runtime_address) + "-");
    }
    else {
        result = builder.CreateSub(originalValue, one, "dec-" + to_string(instruction.runtime_address) + "-");
    }

    // Update EFLAGS/RFLAGS based on the result
    Value* sf = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0), "sf");
    Value* zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0), "zf");
    Value* pf = computeParityFlag(builder, result);

    // OF calculation for INC and DEC
    Value* of = nullptr;
    if (instruction.info.mnemonic == ZYDIS_MNEMONIC_INC) {
        of = builder.CreateICmpEQ(originalValue, ConstantInt::get(originalValue->getType(), -1, true), "of");
    }
    else {
        of = builder.CreateICmpEQ(originalValue, ConstantInt::get(originalValue->getType(), 0, true), "of");
    }

    // AF calculation
    Value* af = builder.CreateICmpNE(builder.CreateAnd(originalValue, ConstantInt::get(originalValue->getType(), 0xF)), builder.CreateAnd(result, ConstantInt::get(result->getType(), 0xF)), "af");

    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_SF, SET_VALUE, sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, pf);
    new_flags = setFlag(context, builder, new_flags, FLAG_OF, SET_VALUE, of);
    new_flags = setFlag(context, builder, new_flags, FLAG_AF, SET_VALUE, af);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);

    SetOperandValue(context, builder, operand, result);
}



void lift_push(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto src = instruction.operands[0]; // value that we are pushing
    auto dest = instruction.operands[2]; 
    auto rsp = instruction.operands[1]; 

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

    auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
    auto result = builder.CreateSub(RspValue, val,"pushing_newrsp-" + to_string(instruction.runtime_address) + "-");

    SetOperandValue(context, builder, rsp, result); // sub rsp 8 first,
    Value* pushing = SetOperandValue(context, builder, dest, Rvalue); // then mov rsp, val


}

void lift_pushfq(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto src = instruction.operands[2]; // value that we are pushing rflags
    auto dest = instruction.operands[1];  // [rsp]
    auto rsp = instruction.operands[0]; // rsp

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

    auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
    auto result = builder.CreateSub(RspValue, val);

    SetOperandValue(context, builder, rsp, result); // sub rsp 8 first,


    SetOperandValue(context, builder, dest, Rvalue); // then mov rsp, val

}

void lift_pop(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0]; // value that we are pushing
    auto src = instruction.operands[2]; 
    auto rsp = instruction.operands[1]; 

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

    auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
    auto result = builder.CreateAdd(RspValue, val,"popping_new_rsp-" + to_string(instruction.runtime_address) + "-");

    SetOperandValue(context, builder, dest, Rvalue); // mov val, rsp first

    SetOperandValue(context, builder, rsp, result); // then add rsp 8



}

void lift_popfq(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[2]; // value that we are pushing
    auto src = instruction.operands[1];  // [rsp]
    auto rsp = instruction.operands[0]; // rsp

    auto Rvalue = GetOperandValue(context, builder, src, dest.size);
    auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

    auto val = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 8); // assuming its x64
    auto result = builder.CreateAdd(RspValue, val,"popfq-" + to_string(instruction.runtime_address) + "-");

    SetOperandValue(context, builder, dest, Rvalue);  // mov val, rsp first
    SetOperandValue(context, builder, rsp, result);  // then add rsp 8



}

void lift_adc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, dest.size);
    Value* cf = getFlag(context, builder, GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS), FLAG_CF);

    cf = builder.CreateZExt(cf, destValue->getType());
    Value* tempResult = builder.CreateAdd(destValue, srcValue, "adcpart1-");
    Value* result = builder.CreateAdd(tempResult, cf,"adc-"+to_string(instruction.runtime_address)+"-");

    // Overflow Flag (OF)
// Compute the sign bits
    Value* msbSrc = builder.CreateICmpSLT(srcValue, ConstantInt::get(srcValue->getType(), 0));
    Value* msbDest = builder.CreateICmpSLT(destValue, ConstantInt::get(destValue->getType(), 0));
    Value* msbResult = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0));

    // Check if source and destination have the same sign
    Value* sameSign = builder.CreateXor(msbSrc, msbDest);
    sameSign = builder.CreateNot(sameSign); // Overflow is possible only if sameSign is true

    // Check if the result's sign bit is different from the operands' sign bits
    Value* signChange = builder.CreateXor(msbResult, msbSrc); // You can also use msbDest here

    // Compute the new overflow flag
    Value* new_of = builder.CreateAnd(sameSign, signChange, "adc-of");
    // Sign Flag (SF)
    Value* new_sf = msbResult;

    // Zero Flag (ZF)
    Value* new_zf = builder.CreateICmpEQ(result, ConstantInt::get(result->getType(), 0), "adc-zf");

    // Auxiliary Carry Flag (AF)
    // TODO

    // Carry Flag (CF)
    Value* new_cf = builder.CreateICmpULT(result, destValue);

    // Parity Flag (PF)
    Value* new_pf = computeParityFlag(builder, result);

    // Update flags
    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, new_of);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, new_sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, new_zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, new_cf);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, new_pf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
    SetOperandValue(context, builder, dest, result);
}

void lift_xadd(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    Value* destValue = GetOperandValue(context, builder, dest, dest.size);
    Value* srcValue = GetOperandValue(context, builder, src, src.size);

    // Perform the xadd operation
    Value* sumValue = builder.CreateAdd(destValue, srcValue, "xadd-sum-"+ to_string(instruction.runtime_address) + "-");

    // Set the new values
    SetOperandValue(context, builder, dest, sumValue);
    SetOperandValue(context, builder, src, destValue);

    // Inline flag calculations
    // Overflow Flag (OF)
    Value* signDest = builder.CreateICmpSLT(destValue, ConstantInt::get(destValue->getType(), 0));
    Value* signSrc = builder.CreateICmpSLT(srcValue, ConstantInt::get(srcValue->getType(), 0));
    Value* signSum = builder.CreateICmpSLT(sumValue, ConstantInt::get(sumValue->getType(), 0));
    Value* sameSignInputs = builder.CreateAnd(signDest, signSrc);
    Value* differentSignResult = builder.CreateXor(signDest, signSum);
    Value* new_of = builder.CreateAnd(sameSignInputs, differentSignResult);


    // Sign Flag (SF)
    Value* new_sf = builder.CreateICmpSLT(sumValue, ConstantInt::get(sumValue->getType(), 0));

    // Zero Flag (ZF)
    Value* new_zf = builder.CreateICmpEQ(sumValue, ConstantInt::get(sumValue->getType(), 0), "zf-xadd");

    // Auxiliary Flag (AF)
    Value* lowNibbleDest = builder.CreateAnd(destValue, 0xF);
    Value* lowNibbleSrc = builder.CreateAnd(srcValue, 0xF);
    Value* new_af = builder.CreateICmpULT(builder.CreateAdd(lowNibbleDest, lowNibbleSrc), lowNibbleDest);

    // Parity Flag (PF)
    Value* new_pf = computeParityFlag(builder, sumValue);

    // Carry Flag (CF)
    Value* new_cf = builder.CreateICmpULT(sumValue, destValue, "cf-xadd");



    // Update the flags in the EFLAGS register
    Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
    Value* new_flags = setFlag(context, builder, old_flags, FLAG_OF, SET_VALUE, new_of);
    new_flags = setFlag(context, builder, new_flags, FLAG_SF, SET_VALUE, new_sf);
    new_flags = setFlag(context, builder, new_flags, FLAG_ZF, SET_VALUE, new_zf);
    new_flags = setFlag(context, builder, new_flags, FLAG_AF, SET_VALUE, new_af);
    new_flags = setFlag(context, builder, new_flags, FLAG_PF, SET_VALUE, new_pf);
    new_flags = setFlag(context, builder, new_flags, FLAG_CF, SET_VALUE, new_cf);

    SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
}




void liftInstruction(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {


    // RIP gets updated before execution of the instruction.
    auto val = llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), instruction.runtime_address);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, val);



    // switch case for lifting all instructions to llvm equivalent semantics
    // TODO: standardize and make it beautiful, multiple arch support
    // I dont want to explain every asm instruction, so probably skip to OperandUtils.cpp, then ROPdetection.cpp
    switch (instruction.info.mnemonic) {
        // MOVES
        case ZYDIS_MNEMONIC_MOVUPS: 
        case ZYDIS_MNEMONIC_MOVZX: 
        case ZYDIS_MNEMONIC_MOVSX: 
        case ZYDIS_MNEMONIC_MOVSXD: 
        case ZYDIS_MNEMONIC_MOV: {
            lift_mov(context,builder,instruction);
            break;
        }                   
        case ZYDIS_MNEMONIC_MOVSB: {
            lift_movsb(context, builder, instruction);
            break;
        }
        // CONDITIONAL MOVES MAYBE MOV DEFAULTAND NOT VERSION TO SAME FUNCTION
        case ZYDIS_MNEMONIC_CMOVZ: {
            lift_cmovz(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVNZ: {
            lift_cmovnz(context, builder, instruction);
            break;
        }           
        case ZYDIS_MNEMONIC_CMOVL: {
            lift_cmovl(context, builder, instruction);
            break;
        }   
        // CMOVNL
        case ZYDIS_MNEMONIC_CMOVB: {
            lift_cmovb(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVNB: {
            lift_cmovnb(context, builder, instruction);
            break;
        }
                                  //CMOVS
        case ZYDIS_MNEMONIC_CMOVNS: {
            lift_cmovns(context, builder, instruction);
            break;
        }
  
        case ZYDIS_MNEMONIC_CMOVBE: {
            lift_cmovbz(context, builder, instruction);
            break;
        } 
        case ZYDIS_MNEMONIC_CMOVNBE: {
            lift_cmovnbz(context, builder, instruction);
            break;
        }
                                   //CMOVL
        case ZYDIS_MNEMONIC_CMOVNL: {
            lift_cmovnl(context, builder, instruction);
            break;
        }        
        case ZYDIS_MNEMONIC_CMOVS: {
            lift_cmovs(context, builder, instruction);
            break;
        }
                                 //CMOVNS
        case ZYDIS_MNEMONIC_CMOVNLE: {
            lift_cmovnle(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVLE: {
            lift_cmovle(context, builder, instruction);
            break;
        }

        case ZYDIS_MNEMONIC_CMOVO: {
            lift_cmovo(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVNO: {
            lift_cmovno(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVP: {
            lift_cmovp(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMOVNP: {
            lift_cmovnp(context, builder, instruction);
            break;
        }
        //SET INSTRUCTIONS
        case ZYDIS_MNEMONIC_SETZ: {
            lift_setz(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETNZ: {
            lift_setnz(context,builder,instruction);
            break;
        }   
        case ZYDIS_MNEMONIC_SETO: {
            lift_seto(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETNO: {
            lift_setno(context, builder, instruction);
            break;
        }
                                 // SETB
        case ZYDIS_MNEMONIC_SETNB: {
            lift_setnb(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETBE: {
            lift_setbe(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETNBE: {
            lift_setnbe(context, builder, instruction);
            break;
        }
                                  //SETS
        case ZYDIS_MNEMONIC_SETNS: {
            lift_setns(context, builder, instruction);
            break;
        }        
        case ZYDIS_MNEMONIC_SETP: {
            lift_setp(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETNP: {
            lift_setnp(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETB: {
            lift_setb(context, builder, instruction);
            break;
        }
                                //SETNB
        case ZYDIS_MNEMONIC_SETS: {
            lift_sets(context, builder, instruction);
            break;
        }
                                //SETNS
        case ZYDIS_MNEMONIC_SETNLE: {
            lift_setnle(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETLE: {
            lift_setle(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SETNL: {
            lift_setnl(context, builder, instruction);
            break;
        }        
        case ZYDIS_MNEMONIC_SETL: {
            lift_setl(context, builder, instruction);
            break;
        }
                                // NEED INSTRINCTICS
        case ZYDIS_MNEMONIC_BSWAP: {
            lift_bswap(context,builder,instruction);
            break;
        }           
                                 // SET FLAGS - REWRITE
        case ZYDIS_MNEMONIC_NEG: {
            lift_neg(context,builder,instruction);
            break;
        }                     
        case ZYDIS_MNEMONIC_BTR: {
            lift_btr(context,builder,instruction);
            break;
        }     
        case ZYDIS_MNEMONIC_BSR: {
            lift_bsr(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_BSF: {
            lift_bsf(context,builder,instruction);
            break;
        }         
        case ZYDIS_MNEMONIC_BTC: {
            lift_btc(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_SAR: {
            lift_sar(context,builder,instruction);
            break;
        }                
        case ZYDIS_MNEMONIC_LAHF: {
            lift_lahf(context,builder,instruction);
            break;
        }               
        case ZYDIS_MNEMONIC_STC: {
            lift_stc(context,builder,instruction);
            break;
        }            
        case ZYDIS_MNEMONIC_CMC: {
            lift_cmc(context,builder,instruction);
            break;
        }            
        case ZYDIS_MNEMONIC_CLC: {
            lift_clc(context,builder,instruction);
            break;
        }          
        case ZYDIS_MNEMONIC_STOSD: {
            lift_stosd(context,builder,instruction);
            break;
        }             
        case ZYDIS_MNEMONIC_CLD: {
            lift_cld(context,builder,instruction);
            break;
        }                      
        case ZYDIS_MNEMONIC_CLI: {
            lift_cli(context,builder,instruction);
            break;
        }                  
        case ZYDIS_MNEMONIC_BTS: {
            lift_bts(context,builder,instruction);
            break;
        }                           
        case ZYDIS_MNEMONIC_BT: {
            lift_bt(context,builder,instruction);
            break;
        }            
        
        case ZYDIS_MNEMONIC_SHL: {
            lift_shl(context,builder,instruction);
            break;
        }                       
        case ZYDIS_MNEMONIC_SHLD: {
            lift_shld(context,builder,instruction);
            break;
        }                       
        case ZYDIS_MNEMONIC_SHRD: {
            lift_shrd(context, builder, instruction);
            break;

        }
        
        case ZYDIS_MNEMONIC_SHR: {
            lift_shr(context,builder,instruction);
            break;
        }         
        case ZYDIS_MNEMONIC_RDTSC: {
            lift_rdtsc(context,builder,instruction);
            break;
        }         
        case ZYDIS_MNEMONIC_RDTSCP: {
            lift_rdtscp(context,builder,instruction);
            break;
        }         
   



        case ZYDIS_MNEMONIC_RCR: {
            lift_rcr(context,builder,instruction);
            break;
        }               
        case ZYDIS_MNEMONIC_RCL: {
            lift_rcl(context,builder,instruction);
            break;
        }               
        case ZYDIS_MNEMONIC_SBB: {
            lift_sbb(context,builder,instruction);
            break;
        }                      
        case ZYDIS_MNEMONIC_ADC: {
            lift_adc(context,builder,instruction);
            break;
        }               
        case ZYDIS_MNEMONIC_XADD: {
            lift_xadd(context, builder, instruction);
            break;
        }
     
        case ZYDIS_MNEMONIC_LEA: {
            lift_lea(context,builder,instruction);
            break;
        }     
        case ZYDIS_MNEMONIC_INC: 
        case ZYDIS_MNEMONIC_DEC: {
            lift_inc_dec(context,builder,instruction);
            break;
        }

        case ZYDIS_MNEMONIC_IMUL:
        case ZYDIS_MNEMONIC_IDIV:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_ADD: {
            lift_add_sub(context, builder, instruction);

            break;
        }        
        
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_ROR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_AND: {
            lift_xor_and_or(context, builder, instruction);

            break;
        }
                               // OTHER
        case ZYDIS_MNEMONIC_PUSH: {
            lift_push(context, builder, instruction);
            break;
        }        

        case ZYDIS_MNEMONIC_PUSHFQ: {
            lift_pushfq(context, builder, instruction);
            break;
        }       
        case ZYDIS_MNEMONIC_POP: {
            lift_pop(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_POPFQ: {
            lift_popfq(context, builder, instruction);
            break;
        }        

        case ZYDIS_MNEMONIC_CDQ: 
        {break; }        
        case ZYDIS_MNEMONIC_CWDE: {
            lift_cwde(context, builder);
            break; 
        }             
        case ZYDIS_MNEMONIC_CWD: {
            lift_cwd(context, builder);
            break; 
        }
        case ZYDIS_MNEMONIC_CQO: {
            lift_cqo(context, builder);
            break;
        }
        case ZYDIS_MNEMONIC_CDQE: {
            lift_cdqe(context, builder);
            break; 
        }       
        case ZYDIS_MNEMONIC_CBW: 
        {
            lift_cbw(context, builder, instruction);
            break; }
        // BRANCHES
        case ZYDIS_MNEMONIC_CALL: {
            lift_call(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_RET: // implement to check if its a real ret or not
        { 
            lift_ret(context, builder, instruction, blockAddresses, run);
            break; }       

        case ZYDIS_MNEMONIC_JMP: {
            lift_jmp(context, builder, instruction, blockAddresses, run);
            break; 
        }        
        
        case ZYDIS_MNEMONIC_JNZ: {
            lift_jnz(context, builder, instruction, blockAddresses);
            break; 
        }       
        case ZYDIS_MNEMONIC_JZ: {
            lift_jz(context, builder, instruction, blockAddresses);
            break; 
        }
        case ZYDIS_MNEMONIC_JB: {
            lift_jb(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_JP: {
            lift_jp(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_JNP: {
            lift_jnp(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_JNB: {
            lift_jnb(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_JBE: {

            lift_jbe(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_JNBE: {

            lift_jnbe(context, builder, instruction, blockAddresses);
            break;
        }            
        case ZYDIS_MNEMONIC_JNLE: {

            lift_jnle(context, builder, instruction, blockAddresses);
            break;
        }            
     
        case ZYDIS_MNEMONIC_JO: {

            lift_jo(context, builder, instruction, blockAddresses);
            break;
        }        
        case ZYDIS_MNEMONIC_JNO: {

            lift_jno(context, builder, instruction, blockAddresses);
            break;
        }        
        case ZYDIS_MNEMONIC_JS: {

            lift_js(context, builder, instruction, blockAddresses);
            break;
        }        
        case ZYDIS_MNEMONIC_JNS: {

            lift_jns(context, builder, instruction, blockAddresses);
            break;
        }
        case ZYDIS_MNEMONIC_TEST: {
            lift_test(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_CMP: {
            lift_cmp(context, builder, instruction);
            break;
        }        
        case ZYDIS_MNEMONIC_NOP:{
            break;
        }
        case ZYDIS_MNEMONIC_XCHG: {
            lift_xchg(context, builder, instruction);
            break;
        }
        case ZYDIS_MNEMONIC_NOT: {
            lift_not(context, builder, instruction);
            break;
        }

        default: {
            cout << "not implemented: " << instruction.info.mnemonic << " runtime: " << hex<<instruction.runtime_address << " " << instruction.text << "\n";
            throw std::runtime_error("not implemented");
            exit(-2);
        }
    }

}
