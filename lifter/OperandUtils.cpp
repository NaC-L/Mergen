#include "includes.h"
// this file is where helper functions reside.

void* file_base_g_operand;
ZyanU8* data_g_operand;

#define printvalue(x) \
    outs() << " " #x " : "; x->print(outs()); outs() << "\n";  outs().flush();


void initBases2(void* file_base, ZyanU8* data) {
	file_base_g_operand = file_base;
	data_g_operand = data;
}

#ifndef TESTFOLDER
#define TESTFOLDER
#endif

// use this or less *special* version of this to compute known bits. USEFUL!!!!!!!!!!!!!!!!!!! FOR FLAGS STUFF
void analyzeValueKnownBits(llvm::Value* value, const llvm::DataLayout& DL) {
	unsigned bitWidth = value->getType()->getIntegerBitWidth();

	KnownBits knownBits;
	computeKnownBits(value, knownBits, DL, 0);

	// At this point, 'knownZeroBits' and 'knownOneBits' are populated.
	printvalue(value);
	outs() << "Known zero bits: " << knownBits.Zero.getZExtValue() << "\n";
	outs() << "Known one bits: " << knownBits.One.getZExtValue() << "\n";
}

// apperantly its only used in optimization pass https://github.com/llvm/llvm-project/blob/main/llvm/lib/Analysis/InstructionSimplify.cpp#L4765 
Value* createSelectFolder(IRBuilder<>& builder, Value* C, Value* True, Value* False, const Twine& Name = "") {
#ifdef TESTFOLDER
	if (auto* CConst = dyn_cast<Constant>(C)) {
		// get C, if C is true, return True, if not False, if C is unknown, return createselect)
		if (auto* CBool = dyn_cast<ConstantInt>(CConst)) {
			if (CBool->isOne()) {
				return True; // C is true
			}
			else if (CBool->isZero()) {
				return False; // C is false
			}
		}
	}
#endif
	return builder.CreateSelect(C, True, False, Name);
}
Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Simplify if either operand is 0
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS; // LHS is 0
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS; // RHS is 0
	}
#endif
	return builder.CreateAdd(LHS, RHS, Name);
}

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "") {
#ifdef TESTFOLDER
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS; // RHS is 0
	}
#endif
	return builder.CreateSub(LHS, RHS, Name);
}

Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Simplify if either operand is 0
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS; // LHS is 0
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS; // RHS is 0
	}
#endif
	return builder.CreateOr(LHS, RHS, Name);
}

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Simplify if either operand is 0
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS; // LHS is 0
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS; // RHS is 0
	}
#endif
	return builder.CreateXor(LHS, RHS, Name);
}

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Simplify if either operand is 0
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return ConstantInt::get(RHS->getType(), 0); // LHS is 0
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return  ConstantInt::get(LHS->getType(), 0); // RHS is 0
	}
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isMinusOne()) return RHS; // LHS is 0
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isMinusOne()) return LHS; // RHS is 0
	}
	// looks correct ? .... try to understand when sober
	if (auto* LHSAndInst = dyn_cast<Instruction>(LHS)) {
		if (LHSAndInst->getOpcode() == Instruction::And) {
			Value* LHSOfLHS = LHSAndInst->getOperand(0);
			Value* RHSOfLHS = LHSAndInst->getOperand(1);
			// Check if RHSOfLHS is a constant, and RHS is also a constant.
			if (auto* RHSOfLHSConst = dyn_cast<ConstantInt>(RHSOfLHS)) {
				if (auto* RHSConst = dyn_cast<ConstantInt>(RHS)) {
					// Combine the masks and apply to LHSOfLHS
					auto CombinedMask = ConstantInt::get(RHS->getType(), RHSOfLHSConst->getValue() & RHSConst->getValue());
					return builder.CreateAnd(LHSOfLHS, CombinedMask, Name);
				}
			}
			if (auto* LHSOfLHSConst = dyn_cast<ConstantInt>(LHSOfLHS)) {
				if (auto* RHSConst = dyn_cast<ConstantInt>(RHS)) {
					// Combine the masks and apply to LHSOfLHS
					auto CombinedMask = ConstantInt::get(RHS->getType(), LHSOfLHSConst->getValue() & RHSConst->getValue());
					return builder.CreateAnd(RHSOfLHS, CombinedMask, Name);
				}
			}
		}
	}

	if (auto* RHSAndInst = dyn_cast<Instruction>(LHS)) {
		if (RHSAndInst->getOpcode() == Instruction::And) {
			Value* LHSOfRHS = RHSAndInst->getOperand(0);
			Value* RHSOfRHS = RHSAndInst->getOperand(1);
			// Check if RHSOfLHS is a constant, and RHS is also a constant.
			if (auto* RHSOfRHSConst = dyn_cast<ConstantInt>(RHSOfRHS)) {
				if (auto* RHSConst = dyn_cast<ConstantInt>(LHS)) {
					// Combine the masks and apply to LHSOfLHS
					auto CombinedMask = ConstantInt::get(RHS->getType(), RHSOfRHSConst->getValue() & RHSConst->getValue());
					return builder.CreateAnd(LHSOfRHS, CombinedMask, Name);
				}
			}
			if (auto* LHSOfRHSConst = dyn_cast<ConstantInt>(LHSOfRHS)) {
				if (auto* RHSConst = dyn_cast<ConstantInt>(LHS)) {
					// Combine the masks and apply to LHSOfLHS
					auto CombinedMask = ConstantInt::get(RHS->getType(), LHSOfRHSConst->getValue() & RHSConst->getValue());
					return builder.CreateAnd(RHSOfRHS, CombinedMask, Name);
				}
			}
		}
	}
#endif
	llvm::DataLayout DL(builder.GetInsertBlock()->getParent()->getParent() ); // Assume 'module' is your llvm::Module*
	analyzeValueKnownBits(LHS, DL);
	return builder.CreateAnd(LHS, RHS, Name);
}

Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "") {
#ifdef TESTFOLDER
	if (TruncInst* truncInst = dyn_cast<TruncInst>(V)) {
		Value* originalValue = truncInst->getOperand(0);
		// Directly truncate the original value to the target type
		return builder.CreateTrunc(originalValue, DestTy, Name);
	}
#endif
	return builder.CreateTrunc(V, DestTy, Name);
}
Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Directly return V if it already has the destination type.
	if (V->getType() == DestTy) {
		return V;
	}
	// assume we have this
	// %trunc2 = trunc iXX %r15 to i8
	// %zext = zext i8 %trunc2 to iYY

	// we want to simplify it to

	// %trunc2 = iXX %trunc2 to iYY
	// %value =  and %trunc2, 0xff




	if (auto* TruncInsts = dyn_cast<TruncInst>(V)) {
		Value* OriginalValue = TruncInsts->getOperand(0); // %trunc2
		Type* OriginalType = OriginalValue->getType(); // iXX
		// iXX == iYY , return OG value
		if (OriginalType->getIntegerBitWidth() == DestTy->getIntegerBitWidth()) {
			return OriginalValue;
		}
		// iXX > iYY , trunc OG value then apply mask
		if (OriginalType->getIntegerBitWidth() > DestTy->getIntegerBitWidth()) {
			auto newval = createTruncFolder(builder, OriginalValue, DestTy, Name);
			uint64_t MaskValue = (1ULL << V->getType()->getIntegerBitWidth()) - 1;
			Value* Mask = ConstantInt::get(DestTy, MaskValue);
			Value* MaskedValue = createAndFolder(builder, newval, Mask, Name);
			return MaskedValue;
		}
		 
	}

	if (auto* ConstInt = dyn_cast<ConstantInt>(V)) {
		return ConstantInt::get(DestTy, ConstInt->getValue().zextOrTrunc(DestTy->getIntegerBitWidth()));
	}

	if (auto* ZExtInsts = dyn_cast<ZExtInst>(V)) {
		return builder.CreateZExt(ZExtInsts->getOperand(0), DestTy, Name);
	}
#endif
	return builder.CreateZExt(V, DestTy, Name);
}


Value* createZExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "") {
	Type* VTy = V->getType();
	if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
		return createZExtFolder(builder,V, DestTy, Name);
	if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
		return createTruncFolder(builder,V, DestTy, Name);
	return V;
}

Value* createSExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "") {
#ifdef TESTFOLDER
	// Directly return V if it already has the destination type.
	if (V->getType() == DestTy) {
		return V;
	}

	// Optimize an SExt following a Trunc from a signed type.
	if (auto* TruncInsts = dyn_cast<TruncInst>(V)) {
		Value* OriginalValue = TruncInsts->getOperand(0);
		Type* OriginalType = OriginalValue->getType();

		// If SExt reverses the Trunc, return the original value directly.
		if (OriginalType == DestTy) {
			return OriginalValue;
		}
	}

	// Simplify SExt of a constant integer.
	if (auto* ConstInt = dyn_cast<ConstantInt>(V)) {
		return ConstantInt::get(DestTy, ConstInt->getValue().sextOrTrunc(DestTy->getIntegerBitWidth()));
	}

	// For an SExt of an SExt, use the wider type directly.
	if (auto* SExtInsts = dyn_cast<SExtInst>(V)) {
		return builder.CreateSExt(SExtInsts->getOperand(0), DestTy, Name);
	}
#endif
	// Default to creating an SExt operation.
	return builder.CreateSExt(V, DestTy, Name);
}

Value* createSExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "") {
	Type* VTy = V->getType();
	if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
		return createSExtFolder(builder, V, DestTy, Name);
	if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
		return createTruncFolder(builder, V, DestTy, Name);
	return V;
}



// create something for trunc and s/z ext, if i8 %val is zext to i64 %val64, then only 1 byte is important, if that is cleared too with an and/shr, then its empty. ex:
/*
%extendedValue13 = zext i8 %trunc11 to i64
%maskedreg14 = and i64 %newreg9, -256
*/


unordered_map<int,Value*> RegisterList;
unordered_map<Flag, Value*> FlagList;

IntegerType* getIntSize(int size, LLVMContext& context) {
	switch (size) {

	case 1: {
		return llvm::Type::getInt1Ty(context);
	}
	case 8: {
		return llvm::Type::getInt8Ty(context);
	}

	case 16: {
		return llvm::Type::getInt16Ty(context);
	}

	case 32: {
		return llvm::Type::getInt32Ty(context);
	}

	case 64: {
		return llvm::Type::getInt64Ty(context);
	}

	case 128: {
		return llvm::Type::getInt128Ty(context);
	}

    default: {
        return llvm::Type::getIntNTy(context, size);
    }

	}
}


void Init_Flags(LLVMContext& context, IRBuilder<>& builder) {

	auto zero = ConstantInt::getSigned(llvm::Type::getInt1Ty(context), 0);

	FlagList[FLAG_CF] = zero;
	FlagList[FLAG_PF] = zero;
	FlagList[FLAG_AF] = zero;
	FlagList[FLAG_ZF] = zero;
	FlagList[FLAG_SF] = zero;
	FlagList[FLAG_TF] = zero;
	FlagList[FLAG_IF] = zero;
	FlagList[FLAG_DF] = zero;
	FlagList[FLAG_OF] = zero;
}

// responsible of operations on RFLAG
Value* setFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue = nullptr) {
	newValue = createTruncFolder(builder,newValue, Type::getInt1Ty(context));
	return FlagList[flag] = newValue;

}
Value* getFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	if (FlagList[flag])
		return FlagList[flag];
	return ConstantInt::getSigned(llvm::Type::getInt1Ty(context), 0);
}





// instead of 1 variable
// have multiple variables that correspond to the flags

void Init_Flags2(LLVMContext& context, IRBuilder<>& builder) {


	auto zero = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 0);
	auto value = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 2); // 2nd bit is reserved and always true

	auto flags = RegisterList[ZYDIS_REGISTER_RFLAGS];

	auto new_flag = createAddFolder(builder,zero, value);

	RegisterList[ZYDIS_REGISTER_RFLAGS] = new_flag;
}


//...
unordered_map<int, Value*> getRegisterList() {
	return RegisterList;
}

//...
void setRegisterList(unordered_map<int, Value*> newRegisterList) {
	RegisterList = newRegisterList;
}



Value* memoryAlloc;

void initMemoryAlloc(Value* allocArg) {
	memoryAlloc = allocArg;
}

unordered_map<int, Value*> InitRegisters(LLVMContext& context, IRBuilder<>& builder,Function* function, ZyanU64 rip) {

	int zydisRegister = ZYDIS_REGISTER_RAX; // Replace with desired key

	auto argEnd = function->arg_end();
	for (auto argIt = function->arg_begin(); argIt != argEnd; ++argIt) {

		if ((zydisRegister == ZYDIS_REGISTER_RSP) || (zydisRegister == ZYDIS_REGISTER_ESP)) {
			// we dont want to register Stack Pointer register as an argument, because then it confuses llvm
			zydisRegister++;
			continue;
		}

		llvm::Argument* arg = &*argIt;
		arg->setName(ZydisRegisterGetString((ZydisRegister)zydisRegister));
		// Check if it's the last argument, if its last argument, create a FLAGS argument where we store flags. probably create a struct for it instead
		if (std::next(argIt) == argEnd) {
			arg->setName("memory");
			memoryAlloc = arg;
		}
		else {
			RegisterList[(ZydisRegister)zydisRegister] = arg;
			zydisRegister++;
		}
	}

	// Initialize flag value, it will be always 2
	Init_Flags(context,builder);



	auto zero = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 0);
	auto value = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), rip);

	// initialize xIP value, should be function start, its here for stuff like getting .data or calling functions
	auto new_rip = createAddFolder(builder,zero, value);
	// move initialized value into map
	RegisterList[ZYDIS_REGISTER_RIP] = new_rip;


	// initialize xSP value, as said, when xSP is not a defined value, optimizations get messy.
	auto stackvalue = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), STACKP_VALUE);
	auto new_stack_pointer = createAddFolder(builder,stackvalue, zero);
	// move initialized value into map
	RegisterList[ZYDIS_REGISTER_RSP] = new_stack_pointer;

	return RegisterList;
}

// get the highest byte
// basically should be 0xFF00
Value* GetValueFromHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg) {


	Value* fullRegisterValue = RegisterList[ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,(ZydisRegister)reg) ];  // Assume we fetch the 64-bit RAX, RCX, etc.

	// Right-shift to bring the high-byte to the least-significant position
	Value* shiftedValue = builder.CreateLShr(fullRegisterValue, 8,"highreg");

	// Mask out other bits to extract the high byte
	Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
	Value* highByteValue = createAndFolder(builder,shiftedValue, FF);

	return highByteValue;
}

// this function will probably cause issues in the future
void SetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder, Value* value) {
#ifdef _DEVELOPMENT
	outs() << " value : "; value->print(outs()); outs() << "\n"; outs().flush();
#endif
	for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
		int shiftAmount = flag;
		Value* shiftedFlagValue = builder.CreateLShr(value, ConstantInt::get(value->getType(), shiftAmount), "setflag"); // Value >> flag
		auto flagValue = createTruncFolder(builder,shiftedFlagValue, Type::getInt1Ty(context)); // i64 ...0001 to 1
#ifdef _DEVELOPMENT
		outs() << " Flag : " << flag << " : "; flagValue->print(outs()); outs() << "\n"; outs().flush();
#endif
		setFlag(context, builder, (Flag)flag, flagValue);
		// shl and or flags to have one big flag
	}
	return;
}
// causes alot of calculations? maybe
Value* GetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder) {
	Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0); // Assuming a 64-bit value for simplicity
	for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
		Value* flagValue = getFlag(context, builder, (Flag)flag);
		int shiftAmount = flag;
		Value* shiftedFlagValue = builder.CreateShl(createZExtFolder(builder,flagValue,Type::getInt64Ty(context)), ConstantInt::get(Type::getInt64Ty(context), shiftAmount));
		rflags = createOrFolder(builder,rflags, shiftedFlagValue,"creatingrflag");
	}
	return rflags;
}


// responsible for retrieving latest llvm SSA value from a asm register
Value* GetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key) {
	// ZYDIS_REGISTER_RFLAGS is bugged and it will return ZYDIS_REGISTER_NONE

	if (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH || key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH) {
		return GetValueFromHighByteRegister(context, builder, key);
	}


	int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP) ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key) : key;


	if (key == ZYDIS_REGISTER_RFLAGS || key == ZYDIS_REGISTER_EFLAGS) {
		return GetRFLAGSValue(context, builder);
	}

	/*
	if (RegisterList.find(newKey) == RegisterList.end()) {
		throw std::runtime_error("register not found"); exit(-1);
	}
	*/


	return RegisterList[newKey];

}






Value* SetValueToHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	int shiftValue = 8;

	// Convert key for high-byte registers to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	// Ensure the value being shifted is of the correct type
	Value* eightBitValue = createAndFolder(builder,value, ConstantInt::get(value->getType(), 0xFF),"eight-bit");
	Value* shiftedValue = builder.CreateShl(eightBitValue, ConstantInt::get(value->getType(), shiftValue),"shl");

	// Create mask and clear the high-byte portion
	Value* mask = ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
	Value* clearedRegister = createAndFolder(builder,fullRegisterValue, mask,"clear-reg");

	shiftedValue = createZExtFolder(builder,shiftedValue, fullRegisterValue->getType() );
	// Set the high-byte portion of the register
	Value* newRegisterValue = createOrFolder(builder,clearedRegister, shiftedValue,"high_byte");

	return newRegisterValue;
}

// I dont remember the logic, however it should be related to this snippet:
// mov eax, 0x12345678
//--- eax = 0x12345678
//mov al,  0xFF
// --- eax = 0X123456FF
Value* SetValueToSubRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	// Convert key for sub-register to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, static_cast<ZydisRegister>(reg));
	Value* fullRegisterValue = RegisterList[fullRegKey];
	fullRegisterValue = createZExtOrTruncFolder(builder,fullRegisterValue, Type::getInt64Ty(context));

	// Determine mask based on sub-register size and position
	uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
	if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
		mask = 0xFFFFFFFFFFFF00FFULL; // Mask for 8 high bits of the lower 16-bit part
	}
	else {
		mask = 0xFFFFFFFFFFFFFF00ULL; // Mask for low 8 bits
	}

	Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
	Value* extendedValue = createZExtFolder(builder,value, Type::getInt64Ty(context), "extendedValue");

	// Mask the full register so that only the sub-register part is set to 0
	Value* maskedFullReg = createAndFolder(builder,fullRegisterValue, maskValue, "maskedreg");

	// Shift the value into the correct position if necessary
	if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
		extendedValue = builder.CreateShl(extendedValue, 8, "shiftedValue");
	}

	// Or the masked full register with the sub-register value to set the byte
	Value* updatedReg = createOrFolder(builder,maskedFullReg, extendedValue, "newreg");

	// Store the updated value back to the full register (if necessary)
	RegisterList[fullRegKey] = updatedReg;

	return updatedReg;
}

// same as above but for 16 bits
Value* SetValueToSubRegister2(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	// Convert key for sub-register to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	// Mask the full register so that only the sub-register part is set to 0

	Value* last4cleared = ConstantInt::get(fullRegisterValue->getType(), 0xFFFFFFFFFFFF0000);
	Value* maskedFullReg = createAndFolder(builder,fullRegisterValue, last4cleared, "maskedreg");
	value = createZExtFolder(builder,value, fullRegisterValue->getType());
	// Or the masked full register with the sub-register value to set the byte
	Value* updatedReg = createOrFolder(builder,maskedFullReg, value, "newreg");

	// Store the updated value back to the full register (if necessary)
	// e.g. RegisterList[fullRegKey] = updatedReg;

	return updatedReg;


}

// responsible for setting a LLVM SSA Value
void SetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key, Value* value) {
    if (
        (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH || key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH)) { // handling all 8 sub-registers
		// ah here
        value = SetValueToSubRegister(context, builder, key, value);
		// ? 
		// should be 0xXXFF

    }

	if ( ( (key >= ZYDIS_REGISTER_R8B) && (key <= ZYDIS_REGISTER_R15B) ) || ((key >= ZYDIS_REGISTER_AL) && (key <= ZYDIS_REGISTER_BL)) || ((key >= ZYDIS_REGISTER_SPL) && (key <= ZYDIS_REGISTER_DIL))) {
		// al here 
		value = SetValueToSubRegister(context, builder, key, value);
		// should be 0xXX 
	}

	if (((key >= ZYDIS_REGISTER_AX) && (key <= ZYDIS_REGISTER_R15W))) {
		value = SetValueToSubRegister2(context, builder, key, value);
	}

	if (key == ZYDIS_REGISTER_RFLAGS) {
		SetRFLAGSValue(context, builder, value);
		return;
	}

    int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP) ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key) : key;

    RegisterList[newKey] = value;
}


// responsible for finding values of addresses ( [] )
Value* GetEffectiveAddress(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize) {
	// First, compute the effective address.
	Value* effectiveAddress = nullptr;

	// Assuming op.mem.base is the base register and op.mem.index is the index register.
	// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.

	Value* baseValue = nullptr;
	if (op.mem.base != ZYDIS_REGISTER_NONE) {
		baseValue = GetRegisterValue(context, builder, op.mem.base);
		baseValue = createZExtFolder(builder,baseValue, Type::getInt64Ty(context));
#ifdef _DEVELOPMENT
		outs() << "	baseValue : ";
		baseValue->print(outs());
		outs() << "\n";
		outs().flush();
#endif
	}

	Value* indexValue = nullptr;
	if (op.mem.index != ZYDIS_REGISTER_NONE) {
		indexValue = GetRegisterValue(context, builder, op.mem.index);

		indexValue = createZExtFolder(builder,indexValue, Type::getInt64Ty(context)); 
#ifdef _DEVELOPMENT
			outs() << "	indexValue : ";
			indexValue->print(outs());
		outs() << "\n";
		outs().flush();
#endif
		if (op.mem.scale > 1) {
			Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
			indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
		}
	}

	if (baseValue && indexValue) {
		effectiveAddress = createAddFolder(builder,baseValue, indexValue, "bvalue_indexvalue_set");
	}
	else if (baseValue) {
		effectiveAddress = baseValue;
	}
	else if (indexValue) {
		effectiveAddress = indexValue;
	}
	else {
		effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
	}

	if (op.mem.disp.value) {
		Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.disp.value);
		effectiveAddress = createAddFolder(builder,effectiveAddress, dispValue, "disp_set");

	}
#ifdef _DEVELOPMENT
	outs() << "	effectiveAddress : ";
	effectiveAddress->print(outs());
	outs() << "\n";
	outs().flush();
#endif
	return createZExtOrTruncFolder(builder,effectiveAddress,getIntSize(possiblesize,context));
}
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Value.h"
#include <vector>
#include <cassert>

using namespace llvm;

class ValueByteReference {
public:
	Value* value;
	short byteOffset;

	ValueByteReference(Value* val, short offset) : value(val), byteOffset(offset) {}
};

class lifterMemoryBuffer {
public:
	std::vector<ValueByteReference*> buffer; // Now storing pointers to ValueByteReference

	lifterMemoryBuffer() : buffer(STACKP_VALUE, nullptr) {} // Initialize with a default size, all nullptrs

	~lifterMemoryBuffer() {
		// Clean up dynamically allocated ValueByteReferences
		for (auto* ref : buffer) {
			delete ref;
		}
	}

	// addValueReference v = 0x12345678 at 0x0
	// v0 v1 v2 v3 =
	// when retrieved
	// v & 0xff + v & 0xff00 + v & 0xff0000 + v & 0xff000000

	void addValueReference(Value* value, unsigned address) {
		unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
		for (unsigned i = 0; i < valueSizeInBytes; i++) {
			// Ensure the buffer is large enough
			delete buffer[address + i];
			// Create a new reference for each byte
			buffer[address + i] = new ValueByteReference(value, i);
		}
	}

	Value* retrieveCombinedValue(llvm::IRBuilder<>& builder, unsigned startAddress, unsigned byteCount) {
		if (byteCount == 0) return nullptr;

		// Early check for contiguous same-source bytes
		Value* firstSource = nullptr;
		bool contiguous = true;

		for (unsigned i = 0; i < byteCount && contiguous; ++i) {
			unsigned currentAddress = startAddress + i;
			if (currentAddress >= buffer.size() || buffer[currentAddress] == nullptr) {
				contiguous = false;
				break;
			}
			if (i == 0) {
				firstSource = buffer[currentAddress]->value;
			}
			else if (buffer[currentAddress]->value != firstSource || buffer[currentAddress]->byteOffset != i) {
				contiguous = false;
			}
		}

		// If all bytes are from the same source and correctly contiguous
		if (contiguous && firstSource != nullptr && byteCount == firstSource->getType()->getIntegerBitWidth() / 8) {
			return firstSource;
		}


		Value* result = nullptr;

		for (unsigned i = 0; i < byteCount; i++) {
			unsigned currentAddress = startAddress + i;
			if (currentAddress < buffer.size() && buffer[currentAddress] != nullptr) {
				auto* ref = buffer[currentAddress];
				llvm::Value* byteValue = extractByte(builder, ref->value, ref->byteOffset);
				if (!result) {
					result = createZExtFolder(builder,byteValue, Type::getIntNTy(builder.getContext(), byteCount * 8));
				}
				else {
					llvm::Value* shiftedByteValue = builder.CreateShl(createZExtFolder(builder,byteValue, Type::getIntNTy(builder.getContext(), byteCount*8) ), llvm::APInt(byteCount * 8, i * 8));
					result = createAddFolder(builder,result, shiftedByteValue,"extractbytesthing");
				}
			}

		}
		return result;
	}

private:
	llvm::Value* extractByte(llvm::IRBuilder<>& builder, llvm::Value* value, unsigned byteOffset) {
		// Assuming the value is a 32-bit integer, adjust the shift amount based on the byte offset
		if (!value) {
			return ConstantInt::get(Type::getInt8Ty(builder.getContext()), 0);
		}
		unsigned shiftAmount = byteOffset * 8;
		llvm::Value* shiftedValue = builder.CreateLShr(value, llvm::APInt(value->getType()->getIntegerBitWidth(), shiftAmount), "extractbyte");
		return createTruncFolder(builder,shiftedValue, Type::getInt8Ty(builder.getContext()));
	}
};


lifterMemoryBuffer globalBuffer;

// responsible for retrieving a value in SSA Value map
Value* GetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize, string address = "") {

	auto type = getIntSize(possiblesize, context);

	switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			Value* value = GetRegisterValue(context, builder, op.reg.value);
			auto opBitWidth = op.size;
			auto typeBitWidth = dyn_cast<IntegerType>(value->getType())->getBitWidth();
			auto new_value =
				createZExtOrTruncFolder(builder,value, type, "trunc");
			return new_value;
		}
		case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
			ConstantInt* val;
			if (op.imm.is_signed) {
				val = (ConstantInt*)llvm::ConstantInt::getSigned(type, op.imm.value.s);
			}
			else {
				val = llvm::ConstantInt::get(context, llvm::APInt(possiblesize, op.imm.value.u));
			}
			return val;
		}
		case ZYDIS_OPERAND_TYPE_MEMORY: {
			// First, compute the effective address.
			Value* effectiveAddress = nullptr;

			// Assuming op.mem.base is the base register and op.mem.index is the index register.
			// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.

			Value* baseValue = nullptr;
			if (op.mem.base != ZYDIS_REGISTER_NONE) {
				baseValue = GetRegisterValue(context, builder, op.mem.base);
				baseValue = createZExtFolder(builder,baseValue, Type::getInt64Ty(context));
#ifdef _DEVELOPMENT
				outs() << "	baseValue : ";
				baseValue->print(outs());
				outs() << "\n";
				outs().flush();
#endif
			}


			Value* indexValue = nullptr;
			if (op.mem.index != ZYDIS_REGISTER_NONE) {
				indexValue = GetRegisterValue(context,builder,op.mem.index);
				indexValue = createZExtFolder(builder,indexValue, Type::getInt64Ty(context));
#ifdef _DEVELOPMENT
				outs() << "	indexValue : ";
				indexValue->print(outs());
				outs() << "\n";
				outs().flush();
#endif
				if (op.mem.scale > 1) {
					Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
					indexValue = builder.CreateMul(indexValue, scaleValue);
				}
			}

			if (baseValue && indexValue) {
				effectiveAddress = createAddFolder(builder,baseValue, indexValue,"bvalue_indexvalue");
			}
			else if (baseValue) {
				effectiveAddress = baseValue;
			}
			else if (indexValue) {
				effectiveAddress = indexValue;
			}
			else {
				effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
			}

			if (op.mem.disp.has_displacement) {
				Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), (int) (op.mem.disp.value) );
				effectiveAddress = createAddFolder(builder,effectiveAddress, dispValue,"memory_addr");
			}
#ifdef _DEVELOPMENT
			outs() << "	effectiveAddress : ";
			effectiveAddress->print(outs());
			outs() << "\n";
			outs().flush();
#endif
			// Load the value from the computed address.
			Type* loadType = getIntSize(possiblesize,context); // Determine based on op.mem.size or some other attribute
			//Value* pointer = builder.CreateIntToPtr(effectiveAddress, loadType->getPointerTo());

			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); // First index is always 0 in this context

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPLoadxd-" + address + "-");



			if (isa<ConstantInt>(effectiveAddress)) {
				ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(effectiveAddress);
				if (!effectiveAddressInt) return nullptr;

				uintptr_t addr = effectiveAddressInt->getZExtValue();
				uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);

				unsigned byteSize = loadType->getIntegerBitWidth() / 8;
				uintptr_t tempValue;

				if (mappedAddr > 0) {
					std::memcpy(&tempValue, reinterpret_cast<const void*>(data_g_operand + mappedAddr), byteSize);

					APInt readValue(byteSize * 8, tempValue);
					Constant* newVal = ConstantInt::get(loadType, readValue);
					if (newVal)
						return newVal;
				}

				if (addr > 0 && addr < STACKP_VALUE) {
					auto newval = globalBuffer.retrieveCombinedValue(builder, addr, byteSize);
					if (newval)
						return newval;
					return ConstantInt::get(getIntSize(byteSize, context), 0);

				}


			}


			/*
			if (isa<ConstantExpr>(pointer)) {
				if (Value* MapValue = GetMemoryValueFromMap(pointer)) { // MMap
					 return createZExtOrTruncFolder(builder,MapValue, loadType);
				}
				if (Operator* op = dyn_cast<Operator>(pointer)) { // Binary
					if (ConstantInt* CI = dyn_cast<ConstantInt>(op->getOperand(0))) {
						uintptr_t addr = CI->getZExtValue();
						uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);
						//cout << "mapppedaddr: " << mappedAddr << " addr: " << addr << "\n";
						if (mappedAddr > 0) {
							unsigned byteSize = loadType->getIntegerBitWidth() / 8;

							uintptr_t tempvalue;
							std::memcpy(&tempvalue, reinterpret_cast<const void*>(data_g_operand + mappedAddr), byteSize);


							APInt readValue(byteSize * 8, tempvalue);
							Constant* newVal = ConstantInt::get(loadType, readValue);
							return newVal;

						}
					}
				}
			}
			*/

			return builder.CreateLoad(loadType, pointer);
		}
		default: {
			throw std::runtime_error("operand type not implemented"); exit(-1);
		}
	}

}

// overwrite the first value with second
Value* merge(LLVMContext& context, IRBuilder<>& builder, Value* existingValue, Value* newValue) {
	// Get the bit width of the existing and new values
	unsigned existingBitWidth = existingValue->getType()->getIntegerBitWidth();
	unsigned newBitWidth = newValue->getType()->getIntegerBitWidth();

	if (newBitWidth >= existingBitWidth) {
		// If the new value is the same size or larger, completely overwrite the existing value
		return newValue;
	}
	// If the new value is smaller, create a mask for the existing value and overwrite it
	// Calculate the mask to keep the upper bits of the existing value
	llvm::APInt maskAPInt = llvm::APInt::getHighBitsSet(existingBitWidth, existingBitWidth - newBitWidth);
	Value* mask = llvm::ConstantInt::get(context, maskAPInt);

	// Apply the mask to the existing value
	Value* maskedExistingValue = createAndFolder(builder,existingValue, mask, "maskedExistingValue");

	// Extend the new value to match the bit width of the existing value
	Value* extendedNewValue = createZExtFolder(builder,newValue, existingValue->getType(), "extendedNewValue");

	// Combine the masked existing value with the extended new value
	return createOrFolder(builder,maskedExistingValue, extendedNewValue, "mergedValue");

}


// responsible for setting a value in SSA Value map
Value* SetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, Value* value, string address = "") {
	switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			SetRegisterValue(context, builder, op.reg.value, value);
			return value;
			break;

		}
		case ZYDIS_OPERAND_TYPE_MEMORY:		{
			// Compute the effective address, as before.
			Value* effectiveAddress = nullptr;

			// Assuming op.mem.base is the base register and op.mem.index is the index register.
			// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.
			// base = zext
			// index = sext
			// imm = sext
			Value* baseValue = nullptr;
			if (op.mem.base != ZYDIS_REGISTER_NONE) {
				baseValue = GetRegisterValue(context, builder, op.mem.base);
				baseValue = createZExtFolder(builder,baseValue, Type::getInt64Ty(context));
#ifdef _DEVELOPMENT
				outs() << "	baseValue : ";
				baseValue->print(outs());
				outs() << "\n";
				outs().flush();
#endif

			}

			Value* indexValue = nullptr;
			if (op.mem.index != ZYDIS_REGISTER_NONE) {
				indexValue = GetRegisterValue(context, builder, op.mem.index);
				indexValue = createZExtFolder(builder,indexValue, Type::getInt64Ty(context));
#ifdef _DEVELOPMENT
				outs() << "	indexValue : ";
				indexValue->print(outs());
				outs() << "\n";
				outs().flush();
#endif
				if (op.mem.scale > 1) {
					Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
					indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
				}
			}

			if (baseValue && indexValue) {
				effectiveAddress = createAddFolder(builder,baseValue, indexValue,"bvalue_indexvalue_set");
			}
			else if (baseValue) {
				effectiveAddress = baseValue;
			}
			else if (indexValue) {
				effectiveAddress = indexValue;
			}
			else {
				effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
			}

			if (op.mem.disp.value) {
				Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.disp.value);
				effectiveAddress = createAddFolder(builder,effectiveAddress, dispValue,"disp_set");
			}

			// Store the value to the computed address.
			Type* storeType = getIntSize(op.size, context); // Determine based on op.mem.size or some other attribute
			//Value* pointer = builder.CreateIntToPtr(effectiveAddress, storeType->getPointerTo());
			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); // First index is always 0 in this context

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,indices,"GEPSTORE-"+ address + "-");
			Value* store = builder.CreateStore(value, pointer);  // Ensure `valueToSet` matches the expected type
#ifdef _DEVELOPMENT
			outs() << "	effectiveAddress : ";
			effectiveAddress->print(outs());
			outs() << "\n";
			outs().flush();
#endif

			if (isa<ConstantInt>(effectiveAddress) ) {

				ConstantInt* effectiveAddressInt = cast<ConstantInt>(effectiveAddress);
				ConstantInt* valueInt = cast<ConstantInt>(value);
				unsigned bitWidth = valueInt->getBitWidth();
				uint64_t dataValue = valueInt->getZExtValue();

				globalBuffer.addValueReference(valueInt, effectiveAddressInt->getZExtValue());
			}


			return store;
		}
		break;

		default: {
			throw std::runtime_error("operand type not implemented"); exit(-1);
            		return nullptr;
		}
	}

}


Value* getMemoryFromValue(LLVMContext& context, IRBuilder<>& builder, Value* value) {

	Type* storeType = value->getType(); // Determine based on op.mem.size or some other attribute
	//Value* pointer = builder.CreateIntToPtr(effectiveAddress, storeType->getPointerTo());
	std::vector<Value*> indices;
	indices.push_back(value); // First index is always 0 in this context

	Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPSTOREVALUE");

	return pointer;

}




Value* getFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	// Create the '1 << position' value
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = builder.CreateShl(one, position, "getflag-shl");

	// Return if the bit at 'position' is set
	Value* and_result = createAndFolder(builder,rflag_var, bit_position, "getflag-and");
	return builder.CreateICmpNE(and_result, ConstantInt::get(context, APInt(64, 0)), "getflag-cmpne");
}

Value* setFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	// Create the '1 << position' value
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = builder.CreateShl(one, position);

	Value* inverse_mask = builder.CreateNot(bit_position);

	// Clear the flag at 'position' in the rflag_var
	Value* cleared_rflag = createAndFolder(builder,rflag_var, inverse_mask);

	// Shift the new value to the correct position
	Value* shifted_newValue = builder.CreateShl(createZExtOrTruncFolder(builder,newValue, Type::getInt64Ty(context)), position, "flagsetweird");
	shifted_newValue = createOrFolder(builder,cleared_rflag, shifted_newValue, "setflag-or");
	SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, shifted_newValue);
	return shifted_newValue;
}



vector<Value*> GetRFLAGS(LLVMContext& context, IRBuilder<>& builder) {
	vector<Value*> rflags;
	for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
		rflags.push_back(getFlag(context, builder, (Flag)flag));
	}
	return rflags;
}



void pushFlags(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, vector<Value*> value, string address = "") {
	auto rsp = GetRegisterValue(context, builder, ZYDIS_REGISTER_RSP);


	for (size_t i = 0; i < value.size(); i += 8) { // merge 8 flags to 1 byte, we can only store i8 (we can, but need to implement some stuff)
		Value* byteVal = ConstantInt::get(Type::getInt8Ty(context), 0); 
		for (size_t j = 0; j < 8 && (i + j) < value.size(); ++j) {
			Value* flag = value[i + j]; 
			Value* extendedFlag = createZExtFolder(builder,flag, Type::getInt8Ty(context),"pushflag1");
			Value* shiftedFlag = builder.CreateShl(extendedFlag, j,"pushflag2");
			byteVal = createOrFolder(builder, byteVal, shiftedFlag,"pushflagbyteval");
		}


		std::vector<Value*> indices;
		indices.push_back(rsp);
		Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPSTORE-" + address + "-");

		// Store the byte
		auto store = builder.CreateStore(byteVal, pointer,"storebyte");
#ifdef _DEVELOPMENT
			printvalue(rsp)
			printvalue(pointer)
			printvalue(byteVal)
			printvalue(store)
#endif
		ConstantInt* rspInt = cast<ConstantInt>(rsp);
		globalBuffer.addValueReference(byteVal, rspInt->getZExtValue());

		rsp = createAddFolder(builder, rsp, ConstantInt::get(rsp->getType(), 1));
	}
}