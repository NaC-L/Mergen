#include "includes.h"
#include "GEPTracker.h"


void* file_base_g_operand;
ZyanU8* data_g_operand;



#ifndef TESTFOLDER
#define TESTFOLDER
#define TESTFOLDER3
#define TESTFOLDER4
#define TESTFOLDER5
#define TESTFOLDER6
#define TESTFOLDER7
#define TESTFOLDER8
#define TESTFOLDERshl
#define TESTFOLDERshr
#endif


KnownBits analyzeValueKnownBits(Value* value, const DataLayout& DL) {
	KnownBits knownBits(64);
	knownBits.resetAll();
	if (value->getType() == Type::getInt128Ty(value->getContext()))
		return knownBits;
	

	return computeKnownBits(value, DL, 3);
}

Value* simplifyValue(Value* v, const DataLayout& DL) {
	
	if (!isa<Instruction>(v))
		return v;

	Instruction* inst = cast<Instruction>(v);


	SimplifyQuery SQ(DL,inst);
	if (auto vconstant = ConstantFoldInstruction(inst, DL)) {
		
		return vconstant;
	}

	if (auto vsimplified = simplifyInstruction(inst, SQ)) {
		/*
		if (isa<PoisonValue>(vsimplified)) // if poison it should be 0 for shifts, can other operations generate poison without a poison value anyways?
			return ConstantInt::get(v->getType(), 0);
			*/
		return vsimplified;
	}	

	return v;
}

Value* simplifyLoadValue(Value* v) {


	Instruction* inst = cast<Instruction>(v);
	Module* M = (inst->getModule());
	Function& F = *inst->getFunction();

	llvm::IRBuilder<> builder(&*F.getEntryBlock().getFirstInsertionPt());
	auto LInst = cast<LoadInst>(v);
	auto GEPVal = LInst->getPointerOperand();

	if (!isa<GetElementPtrInst>(GEPVal))
		return nullptr;

	auto GEPInst = cast<GetElementPtrInst>(GEPVal);

	Value* pv = GEPInst->getPointerOperand();
	Value* idxv = GEPInst->getOperand(1);
	unsigned byteCount = v->getType()->getIntegerBitWidth() / 8;

	//printvalueforce(v)
	//printvalueforce(pv)
	//printvalueforce(idxv)
	//printvalueforce2(byteCount)

	auto retVal = GEPStoreTracker::getValueAt(builder, pv, idxv, byteCount);

	//printvalueforce(retVal)
	return retVal;

}

Value* simplifyValueLater(Value* v, const DataLayout& DL) {

	//printvalueforce(v)
	if (!isa<Instruction>(v))
		return v;
	if (!isa<LoadInst>(v)) 
		return simplifyValue(v, DL);

	


	
		
	
	auto loadInst = cast<LoadInst>(v);
	//printvalueforce(loadInst)
	auto GEP = loadInst->getOperand(loadInst->getNumOperands() - 1);
	//printvalueforce(GEP)
	auto gepInst = cast<GetElementPtrInst>(GEP);
	auto effectiveAddress = gepInst->getOperand(gepInst->getNumOperands() - 1);
	//printvalueforce(effectiveAddress)
	if (!isa<ConstantInt>(effectiveAddress)) {
		return v;
	}


	ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(effectiveAddress);
	if (!effectiveAddressInt) return nullptr;



	uintptr_t addr = effectiveAddressInt->getZExtValue();

	// also the second case
	if (addr > 0 && addr < STACKP_VALUE) {
		if (auto SLV = simplifyLoadValue(v))
			return SLV;
	}

	


	unsigned byteSize = v->getType()->getIntegerBitWidth() / 8;
/*
	uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);
	uintptr_t tempValue;

	if (mappedAddr > 0) {
		std::memcpy(&tempValue, reinterpret_cast<const void*>(data_g_operand + mappedAddr), byteSize);

		APInt readValue(byteSize * 8, tempValue);
		Constant* newVal = ConstantInt::get(v->getType(), readValue);
		if (newVal)
			return newVal;
	}
*/
	if (APInt* ConstantValue = BinaryOperations::readMemory(addr, byteSize)) {
		APInt value = *ConstantValue;
		Constant* newVal = ConstantInt::get(v->getType(), value);

		if (newVal)
			return newVal;
	}

	return v;
}


Value* createSelectFolder(IRBuilder<>& builder, Value* C, Value* True, Value* False, const Twine& Name ) {
#ifdef TESTFOLDER
	if (auto* CConst = dyn_cast<Constant>(C)) {

		if (auto* CBool = dyn_cast<ConstantInt>(CConst)) {
			if (CBool->isOne()) {
				return True;
			}
			else if (CBool->isZero()) {
				return False;
			}
		}
	}
#endif	
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	return simplifyValue(builder.CreateSelect(C, True, False, Name), DL);
}
Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {
#ifdef TESTFOLDER3

	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS;
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS;
	}
#endif
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	return simplifyValue( builder.CreateAdd(LHS, RHS, Name), DL);
}

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {
#ifdef TESTFOLDER4
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS;
	}
#endif	
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	return simplifyValue( builder.CreateSub(LHS, RHS, Name) , DL);
}

Value* foldLShrKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {




	if (RHS.hasConflict() || LHS.hasConflict() || !RHS.isConstant() || RHS.getBitWidth() > 64 || LHS.isUnknown() || LHS.getBitWidth() <= 1)
		return nullptr;

	APInt shiftAmount = RHS.getConstant();
	unsigned shiftSize = shiftAmount.getZExtValue();

	if (shiftSize >= LHS.getBitWidth())
		return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), 0);;

	KnownBits result(LHS.getBitWidth());
	result.One = LHS.One.lshr(shiftSize);
	result.Zero = LHS.Zero.lshr(shiftSize) | APInt::getHighBitsSet(LHS.getBitWidth(), shiftSize);

	if (!(result.Zero | result.One).isAllOnes()) {
		return nullptr;
	}

	return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), result.getConstant());
}

Value* foldShlKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {
	if (RHS.hasConflict() || LHS.hasConflict() || !RHS.isConstant() || RHS.getBitWidth() > 64 || LHS.isUnknown() || LHS.getBitWidth() <= 1)
		return nullptr;

	APInt shiftAmount = RHS.getConstant();
	unsigned shiftSize = shiftAmount.getZExtValue();

	if (shiftSize >= LHS.getBitWidth())
		return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), 0);

	KnownBits result(LHS.getBitWidth());
	result.One = LHS.One.shl(shiftSize);
	result.Zero = LHS.Zero.shl(shiftSize) | APInt::getLowBitsSet(LHS.getBitWidth(), shiftSize);

	if (result.hasConflict() || !result.isConstant()) {
		return nullptr;
	}

	return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), result.getConstant());
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {

	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDERshl




	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

	if (Value* knownBitsShl = foldShlKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
		return knownBitsShl;
	}

#endif


	return simplifyValue( builder.CreateShl(LHS, RHS, Name), DL);
}

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {

	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDERshr



	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

	if (Value* knownBitsLshr = foldLShrKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
		printvalue(knownBitsLshr)
		return knownBitsLshr;
	}

#endif


	return simplifyValue(builder.CreateLShr(LHS, RHS, Name),DL);
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, uintptr_t RHS, const Twine& Name ) {
	return createShlFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, APInt RHS, const Twine& Name ) {
	return createShlFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}



Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, uintptr_t RHS, const Twine& Name ) {
	return createLShrFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, APInt RHS, const Twine& Name ) {
	return createLShrFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}


Value* foldOrKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {

	if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() || RHS.isUnknown() || LHS.getBitWidth() != RHS.getBitWidth() || !RHS.isConstant() || LHS.getBitWidth() <= 1 || RHS.getBitWidth() < 1 || RHS.getBitWidth() > 64 || LHS.getBitWidth() > 64) {
		return nullptr;
	}



	KnownBits combined;
	combined.One = LHS.One | RHS.One;
	combined.Zero = LHS.Zero & RHS.Zero;

	if (!combined.isConstant() || combined.hasConflict()) {
		return nullptr;
	}

	APInt resultValue = combined.One;
	return ConstantInt::get(Type::getIntNTy(context, combined.getBitWidth()), resultValue);
}


Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER5

	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS;
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS;
	}

	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

	if (Value* knownBitsAnd = foldOrKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
		return knownBitsAnd;
	}
	if (Value* knownBitsAnd = foldOrKnownBits(builder.getContext(), KnownRHS, KnownLHS)) {
		return knownBitsAnd;
	}
#endif


	return simplifyValue( builder.CreateOr(LHS, RHS, Name),DL );
}


Value* foldXorKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {


	if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() || RHS.isUnknown() || !RHS.isConstant() || LHS.getBitWidth() != RHS.getBitWidth() || RHS.getBitWidth() <= 1 || LHS.getBitWidth() <= 1 || RHS.getBitWidth() > 64 || LHS.getBitWidth() > 64) {
		return nullptr;
	}

	if (!((LHS.Zero | LHS.One) & RHS.One).eq(RHS.One)) { 
		return nullptr;
	}
	APInt resultValue = LHS.One ^ RHS.One;

	return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), resultValue);
}

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {
#ifdef TESTFOLDER6

	if (LHS == RHS) {
		return ConstantInt::get(LHS->getType(), 0);
	}

	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return RHS;
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return LHS;
	}


#endif
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);


	if (auto V = foldXorKnownBits(builder.getContext(), KnownLHS, KnownRHS))
		return V;

	return simplifyValue(builder.CreateXor(LHS, RHS, Name), DL);
}

std::optional<bool> foldKnownBits(CmpInst::Predicate P, KnownBits LHS, KnownBits RHS) {

	switch (P) {
	case CmpInst::ICMP_EQ:
		return KnownBits::eq(LHS, RHS);
	case CmpInst::ICMP_NE:
		return KnownBits::ne(LHS, RHS);
	case CmpInst::ICMP_UGT:
		return KnownBits::ugt(LHS, RHS);
	case CmpInst::ICMP_UGE:
		return KnownBits::uge(LHS, RHS);
	case CmpInst::ICMP_ULT:
		return KnownBits::ult(LHS, RHS);
	case CmpInst::ICMP_ULE:
		return KnownBits::ule(LHS, RHS);
	case CmpInst::ICMP_SGT:
		return KnownBits::sgt(LHS, RHS);
	case CmpInst::ICMP_SGE:
		return KnownBits::sge(LHS, RHS);
	case CmpInst::ICMP_SLT:
		return KnownBits::slt(LHS, RHS);
	case CmpInst::ICMP_SLE:
		return KnownBits::sle(LHS, RHS);
	}

	return nullopt;
}

Value* createICMPFolder(IRBuilder<>& builder, CmpInst::Predicate P, Value* LHS, Value* RHS, const Twine& Name ) {
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

	if (std::optional<bool> v = foldKnownBits(P, KnownLHS, KnownRHS)) {
		return ConstantInt::get(Type::getInt1Ty(builder.getContext()), v.value());
	}

	return simplifyValue( builder.CreateICmp(P, LHS, RHS, Name), DL);
}

Value* foldAndKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {

	if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() || RHS.isUnknown() || !RHS.isConstant() || LHS.getBitWidth() != RHS.getBitWidth() || RHS.getBitWidth() <= 1 || LHS.getBitWidth() <= 1 || RHS.getBitWidth() > 64 || LHS.getBitWidth() > 64) {
		return nullptr;
	}

	if (!((LHS.Zero | LHS.One) & RHS.One).eq(RHS.One)) {
		return nullptr;
	}
	APInt resultValue = LHS.One & RHS.One;

	return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), resultValue);
}

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name ) {
#ifdef TESTFOLDER
	
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isZero()) return ConstantInt::get(RHS->getType(), 0);
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isZero()) return  ConstantInt::get(LHS->getType(), 0);
	}
	if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
		if (LHSConst->isMinusOne()) return RHS;
	}
	if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
		if (RHSConst->isMinusOne()) return LHS;
	}
	
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
	KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
	KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

	if (Value* knownBitsAnd = foldAndKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
		return knownBitsAnd;
	}
	if (Value* knownBitsAnd = foldAndKnownBits(builder.getContext(), KnownRHS, KnownLHS)) {
		return knownBitsAnd;
	}

#endif
	return simplifyValue( builder.CreateAnd(LHS, RHS, Name), DL);
}

// - probably not needed anymore
Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name ) {
	Value* resulttrunc = builder.CreateTrunc(V, DestTy, Name);
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER7
	
	KnownBits KnownRHS = analyzeValueKnownBits(resulttrunc, DL);
	if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 && KnownRHS.isConstant())
		return ConstantInt::get(DestTy, KnownRHS.getConstant());
#endif
	return simplifyValue(resulttrunc, DL);
}



Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name ) {
	auto resultzext = builder.CreateZExt(V, DestTy, Name);
	DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER8

	KnownBits KnownRHS = analyzeValueKnownBits(resultzext, DL);
	if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 && KnownRHS.isConstant())
		return ConstantInt::get(DestTy, KnownRHS.getConstant());
#endif

	return resultzext;
}


Value* createZExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name ) {
	Type* VTy = V->getType();
	if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
		return createZExtFolder(builder, V, DestTy, Name);
	if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
		return createTruncFolder(builder, V, DestTy, Name);
	return V;
}

Value* createSExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name ) {
#ifdef TESTFOLDER9

	if (V->getType() == DestTy) {
		return V;
	}


	if (auto* TruncInsts = dyn_cast<TruncInst>(V)) {
		Value* OriginalValue = TruncInsts->getOperand(0);
		Type* OriginalType = OriginalValue->getType();


		if (OriginalType == DestTy) {
			return OriginalValue;
		}
	}


	if (auto* ConstInt = dyn_cast<ConstantInt>(V)) {
		return ConstantInt::get(DestTy, ConstInt->getValue().sextOrTrunc(DestTy->getIntegerBitWidth()));
	}


	if (auto* SExtInsts = dyn_cast<SExtInst>(V)) {
		return builder.CreateSExt(SExtInsts->getOperand(0), DestTy, Name);
	}
#endif

	return builder.CreateSExt(V, DestTy, Name);
}

Value* createSExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name ) {
	Type* VTy = V->getType();
	if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
		return createSExtFolder(builder, V, DestTy, Name);
	if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
		return createTruncFolder(builder, V, DestTy, Name);
	return V;
}





/*
%extendedValue13 = zext i8 %trunc11 to i64
%maskedreg14 = and i64 %newreg9, -256
*/


unordered_map<int,Value*> RegisterList;
unordered_map<Flag, Value*> FlagList;

IntegerType* getIntSize(int size, LLVMContext& context) {
	switch (size) {

	case 1: {
		return Type::getInt1Ty(context);
	}
	case 8: {
		return Type::getInt8Ty(context);
	}

	case 16: {
		return Type::getInt16Ty(context);
	}

	case 32: {
		return Type::getInt32Ty(context);
	}

	case 64: {
		return Type::getInt64Ty(context);
	}

	case 128: {
		return Type::getInt128Ty(context);
	}

    default: {
        return Type::getIntNTy(context, size);
    }

	}
}


void Init_Flags(LLVMContext& context, IRBuilder<>& builder) {

	auto zero = ConstantInt::getSigned(Type::getInt1Ty(context), 0);
	auto one = ConstantInt::getSigned(Type::getInt1Ty(context), 1);

	FlagList[FLAG_CF] = zero;
	FlagList[FLAG_PF] = zero;
	FlagList[FLAG_AF] = zero;
	FlagList[FLAG_ZF] = zero;
	FlagList[FLAG_SF] = zero;
	FlagList[FLAG_TF] = zero;
	FlagList[FLAG_IF] = zero;
	FlagList[FLAG_DF] = zero;
	FlagList[FLAG_OF] = zero;

	FlagList[FLAG_RESERVED1] = one; 
}


Value* setFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue = nullptr) {
	newValue = createTruncFolder(builder,newValue, Type::getInt1Ty(context));

	if (flag == FLAG_RESERVED1 
		|| flag == FLAG_RESERVED5
		|| flag == FLAG_IF
		|| flag == FLAG_DF
		)
		return nullptr;

	auto one = ConstantInt::getSigned(Type::getInt1Ty(context), 1);

	return FlagList[flag] = newValue;

}
Value* getFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	if (FlagList[flag])
		return FlagList[flag];
	return ConstantInt::getSigned(Type::getInt1Ty(context), 0);
}








void Init_Flags2(LLVMContext& context, IRBuilder<>& builder) {


	auto zero = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 0);
	auto value = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 2); 

	auto flags = RegisterList[ZYDIS_REGISTER_RFLAGS];

	auto new_flag = createAddFolder(builder,zero, value);

	RegisterList[ZYDIS_REGISTER_RFLAGS] = new_flag;
}



unordered_map<int, Value*> getRegisterList() {
	return RegisterList;
}


void setRegisterList(unordered_map<int, Value*> newRegisterList) {
	RegisterList = newRegisterList;
}



Value* memoryAlloc;

void initMemoryAlloc(Value* allocArg) {
	memoryAlloc = allocArg;
}
Value* getMemory() {
	return memoryAlloc;
}

// replace it so that we can select we want rcx, rdx, r8, r9 and rest pushed to stack or everything is unknown

unordered_map<Value*, int> flipRegisterMap() {
	unordered_map<Value*, int> RevMap;
	for (const auto& pair : RegisterList) {
		RevMap[pair.second] = pair.first;
	}
	/*for (const auto& pair : FlagList) {
		RevMap[pair.second] = pair.first;
	}*/
	return RevMap;
}

unordered_map<int, Value*> InitRegisters(LLVMContext& context, IRBuilder<>& builder,Function* function, ZyanU64 rip) {

	int zydisRegister = ZYDIS_REGISTER_RAX; 

	auto argEnd = function->arg_end();
	for (auto argIt = function->arg_begin(); argIt != argEnd; ++argIt) {

		/*if ((zydisRegister == ZYDIS_REGISTER_RSP) || (zydisRegister == ZYDIS_REGISTER_ESP)) {
			
			zydisRegister++;
			continue;
		}*/

		Argument* arg = &*argIt;
		arg->setName(ZydisRegisterGetString((ZydisRegister)zydisRegister));
		
		if (std::next(argIt) == argEnd) {
			arg->setName("memory");
			memoryAlloc = arg;
		}
		else {
			RegisterList[(ZydisRegister)zydisRegister] = arg;
			zydisRegister++;
		}
	}

	
	Init_Flags(context,builder);



	auto zero = cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), 0));
	auto value = cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), rip));
	
	auto new_rip = createAddFolder(builder,zero, value);
	
	RegisterList[ZYDIS_REGISTER_RIP] = new_rip;


	
	auto stackvalue = cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));
	auto new_stack_pointer = createAddFolder(builder,stackvalue, zero);
	
	RegisterList[ZYDIS_REGISTER_RSP] = new_stack_pointer;

	return RegisterList;
}



Value* GetValueFromHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg) {


	Value* fullRegisterValue = RegisterList[ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,(ZydisRegister)reg) ];  

	
	Value* shiftedValue = createLShrFolder(builder,fullRegisterValue, 8,"highreg");

	
	Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
	Value* highByteValue = createAndFolder(builder,shiftedValue, FF, "highByte");

	return highByteValue;
}


void SetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder, Value* value) {
#ifdef _DEVELOPMENT
	outs() << " value : "; value->print(outs()); outs() << "\n"; outs().flush();
#endif
	for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
		int shiftAmount = flag;
		Value* shiftedFlagValue = createLShrFolder(builder,value, ConstantInt::get(value->getType(), shiftAmount), "setflag"); 
		auto flagValue = createTruncFolder(builder,shiftedFlagValue, Type::getInt1Ty(context),"flagtrunc"); 

		setFlag(context, builder, (Flag)flag, flagValue);
		
	}
	return;
}

Value* GetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder) {
	Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0); 
	for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
		Value* flagValue = getFlag(context, builder, (Flag)flag);
		int shiftAmount = flag;
		Value* shiftedFlagValue = createShlFolder(builder,createZExtFolder(builder,flagValue,Type::getInt64Ty(context),"createrflag1"), ConstantInt::get(Type::getInt64Ty(context), shiftAmount), "createrflag2");
		rflags = createOrFolder(builder,rflags, shiftedFlagValue,"creatingrflag");
	}
	return rflags;
}


Value* GetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key) {

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

	printvalue(RegisterList[newKey]);

	return RegisterList[newKey];

}






Value* SetValueToHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	int shiftValue = 8;

	
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	
	Value* eightBitValue = createAndFolder(builder,value, ConstantInt::get(value->getType(), 0xFF),"eight-bit");
	Value* shiftedValue = createShlFolder(builder,eightBitValue, ConstantInt::get(value->getType(), shiftValue),"shl");

	
	Value* mask = ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
	Value* clearedRegister = createAndFolder(builder,fullRegisterValue, mask,"clear-reg");

	shiftedValue = createZExtFolder(builder,shiftedValue, fullRegisterValue->getType() );
	
	Value* newRegisterValue = createOrFolder(builder,clearedRegister, shiftedValue,"high_byte");

	return newRegisterValue;
}






Value* SetValueToSubRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, static_cast<ZydisRegister>(reg));
	Value* fullRegisterValue = RegisterList[fullRegKey];
	fullRegisterValue = createZExtOrTruncFolder(builder,fullRegisterValue, Type::getInt64Ty(context));

	
	uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
	if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
		mask = 0xFFFFFFFFFFFF00FFULL; 
	}
	else {
		mask = 0xFFFFFFFFFFFFFF00ULL; 
	}

	Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
	Value* extendedValue = createZExtFolder(builder,value, Type::getInt64Ty(context), "extendedValue");

	
	Value* maskedFullReg = createAndFolder(builder,fullRegisterValue, maskValue, "maskedreg");

	
	if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
		extendedValue = createShlFolder(builder,extendedValue, 8, "shiftedValue");
	}


	
	Value* updatedReg = createOrFolder(builder,maskedFullReg, extendedValue, "newreg");


	printvalue(fullRegisterValue)
	printvalue(maskValue)
	printvalue(maskedFullReg)
	printvalue(extendedValue)
	printvalue(updatedReg)


	
	RegisterList[fullRegKey] = updatedReg;

	return updatedReg;
}


Value* SetValueToSubRegister2(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	

	Value* last4cleared = ConstantInt::get(fullRegisterValue->getType(), 0xFFFFFFFFFFFF0000);
	Value* maskedFullReg = createAndFolder(builder,fullRegisterValue, last4cleared, "maskedreg");
	value = createZExtFolder(builder,value, fullRegisterValue->getType());
	
	Value* updatedReg = createOrFolder(builder,maskedFullReg, value, "newreg");

	
	

	return updatedReg;


}

void SetRegisterValue(LLVMContext& context, int key, Value* value) {

	int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP) ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key) : key;

	RegisterList[newKey] = value;
}

void SetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key, Value* value) {
    if (
        (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH || key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH)) { 
		
        value = SetValueToSubRegister(context, builder, key, value);
		
		

    }

	if ( ( (key >= ZYDIS_REGISTER_R8B) && (key <= ZYDIS_REGISTER_R15B) ) || ((key >= ZYDIS_REGISTER_AL) && (key <= ZYDIS_REGISTER_BL)) || ((key >= ZYDIS_REGISTER_SPL) && (key <= ZYDIS_REGISTER_DIL))) {
		
		value = SetValueToSubRegister(context, builder, key, value);
		
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



Value* GetEffectiveAddress(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize) {
	
	Value* effectiveAddress = nullptr;

	
	

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


// replace it with https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Analysis/MemoryLocation.h#L228 but I think this might be better after build, not while building
class ValueByteReference {
public:
	Value* value;
	short byteOffset;

	ValueByteReference(Value* val, short offset) : value(val), byteOffset(offset) {}
};

class lifterMemoryBuffer {
public:
	std::vector<ValueByteReference*> buffer; 

	lifterMemoryBuffer() : buffer(STACKP_VALUE, nullptr) {} 

	~lifterMemoryBuffer() {
		
		for (auto* ref : buffer) {
			delete ref;
		}
	}

	void addValueReference(Value* value, unsigned address) {
		unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
		for (unsigned i = 0; i < valueSizeInBytes; i++) {
			
			delete buffer[address + i];
			
			buffer[address + i] = new ValueByteReference(value, i);
		}
	}

	Value* retrieveCombinedValue(IRBuilder<>& builder, unsigned startAddress, unsigned byteCount) {
		LLVMContext& context = builder.getContext();
		if (byteCount == 0) return nullptr;

		
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

		
		if (contiguous && firstSource != nullptr && byteCount == firstSource->getType()->getIntegerBitWidth() / 8) {
			return firstSource;
		}

		// supposed to return 0 if never used, wtf?
		if (firstSource == nullptr) {
			return ConstantInt::get( Type::getIntNTy(context,byteCount), 0);
		}

		Value* result = nullptr;

		for (unsigned i = 0; i < byteCount; i++) {
			unsigned currentAddress = startAddress + i;
			if (currentAddress < buffer.size() && buffer[currentAddress] != nullptr) {
				auto* ref = buffer[currentAddress];
				Value* byteValue = extractByte(builder, ref->value, ref->byteOffset);
				if (!result) {
					result = createZExtFolder(builder,byteValue, Type::getIntNTy(builder.getContext(), byteCount * 8));
				}
				else {
					Value* shiftedByteValue = createShlFolder(builder, createZExtFolder(builder,byteValue, Type::getIntNTy(builder.getContext(), byteCount*8) ), APInt(byteCount * 8, i * 8));
					result = createAddFolder(builder,result, shiftedByteValue,"extractbytesthing");
				}
			}

		}
		return result;
	}

private:
	Value* extractByte(IRBuilder<>& builder, Value* value, unsigned byteOffset) {
		
		if (!value) {
			return ConstantInt::get(Type::getInt8Ty(builder.getContext()), 0);
		}
		unsigned shiftAmount = byteOffset * 8;
		Value* shiftedValue = createLShrFolder(builder,value, APInt(value->getType()->getIntegerBitWidth(), shiftAmount), "extractbyte");
		return createTruncFolder(builder,shiftedValue, Type::getInt8Ty(builder.getContext()));
	}
};


lifterMemoryBuffer globalBuffer;


Value* GetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize, string address) {

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
				val = ConstantInt::getSigned(type, op.imm.value.s);
			}
			else {
				val = ConstantInt::get(context, APInt(possiblesize, op.imm.value.u));
			}
			return val;
		}
		case ZYDIS_OPERAND_TYPE_MEMORY: {
			
			Value* effectiveAddress = nullptr;

			
			

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
			
			Type* loadType = getIntSize(possiblesize,context); 
			

			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); 

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPLoadxd-" + address + "-");


			auto retval = builder.CreateLoad(loadType, pointer, "Loadxd-" + address + "-");

			/*
			GEPStoreTracker::insertMemoryOp(cast<StoreInst>(retval));
			if (Value* solvedLoad = GEPStoreTracker::solveLoad(retval))
				return solvedLoad;
			*/

			if (isa<ConstantInt>(effectiveAddress)) {
				ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(effectiveAddress);
				if (!effectiveAddressInt) return nullptr;

				uintptr_t addr = effectiveAddressInt->getZExtValue();

				unsigned byteSize = loadType->getIntegerBitWidth() / 8;
				
				

				if (APInt* readValue = BinaryOperations::readMemory(addr, byteSize)) {
					APInt value = *readValue;
					Constant* newVal = ConstantInt::get(loadType, value);

					if (newVal)
						return newVal;
				}

				if (addr > 0 && addr < STACKP_VALUE) {
					auto newval = globalBuffer.retrieveCombinedValue(builder, addr, byteSize);
					if (newval) {
						auto retval = simplifyValue(newval,
							builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());
						printvalue(retval);
						return retval;
					}
					return ConstantInt::get(getIntSize(byteSize, context), 0);
				}
			}
			
			pointer = simplifyValue(pointer,
				builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

			/*
			if (isa<ConstantExpr>(pointer)) {
				if (Value* MapValue = GetMemoryValueFromMap(pointer)) { 
					 return createZExtOrTruncFolder(builder,MapValue, loadType);
				}
				if (Operator* op = dyn_cast<Operator>(pointer)) { 
					if (ConstantInt* CI = dyn_cast<ConstantInt>(op->getOperand(0))) {
						uintptr_t addr = CI->getZExtValue();
						uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);
						
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

			GEPStoreTracker::insertInfo(memoryAlloc, effectiveAddress, nullptr, false);

			printvalue(retval);

			return retval;
		}
		default: {
			throw std::runtime_error("operand type not implemented"); exit(-1);
		}
	}

}


Value* merge(LLVMContext& context, IRBuilder<>& builder, Value* existingValue, Value* newValue) {
	
	unsigned existingBitWidth = existingValue->getType()->getIntegerBitWidth();
	unsigned newBitWidth = newValue->getType()->getIntegerBitWidth();

	if (newBitWidth >= existingBitWidth) {
		
		return newValue;
	}
	
	
	APInt maskAPInt = APInt::getHighBitsSet(existingBitWidth, existingBitWidth - newBitWidth);
	Value* mask = ConstantInt::get(context, maskAPInt);

	
	Value* maskedExistingValue = createAndFolder(builder,existingValue, mask, "maskedExistingValue");

	
	Value* extendedNewValue = createZExtFolder(builder,newValue, existingValue->getType(), "extendedNewValue");

	
	return createOrFolder(builder,maskedExistingValue, extendedNewValue, "mergedValue");

}



Value* SetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, Value* value, string address) {

	value = simplifyValue(value, builder.GetInsertBlock()->getParent()->getParent()->getDataLayout() );

	switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			SetRegisterValue(context, builder, op.reg.value, value);
			return value;
			break;

		}
		case ZYDIS_OPERAND_TYPE_MEMORY:		{
			
			Value* effectiveAddress = nullptr;

			
			
			
			
			
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

			
			Type* storeType = getIntSize(op.size, context); 
			
			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); 

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,indices,"GEPSTORE-"+ address + "-");

			pointer = simplifyValue(pointer,
				builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

			Value* store = builder.CreateStore(value, pointer);  
#ifdef _DEVELOPMENT
			outs() << "	effectiveAddress : ";
			effectiveAddress->print(outs());
			outs() << "\n";
			outs().flush();
#endif

			// if effectiveAddress is not pointing at stack, its probably self modifying code
			// if effectiveAddress and value is consant we can say its a self modifying code and modify the binary
			if (isa<ConstantInt>(effectiveAddress) ) {

				ConstantInt* effectiveAddressInt = cast<ConstantInt>(effectiveAddress);
				auto addr = effectiveAddressInt->getZExtValue();
				if (addr > 0 && addr < STACKP_VALUE) {
					globalBuffer.addValueReference(value, addr);
				}
			}

			GEPStoreTracker::insertMemoryOp(cast<StoreInst>(store));
			GEPStoreTracker::insertInfo(memoryAlloc, effectiveAddress, value, true);

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

	Type* storeType = value->getType(); 
	
	std::vector<Value*> indices;
	indices.push_back(value); 

	Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPSTOREVALUE");

	return pointer;

}




Value* getFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = createShlFolder(builder,one, position, "getflag-shl");

	
	Value* and_result = createAndFolder(builder,rflag_var, bit_position, "getflag-and");
	return builder.CreateICmpNE(and_result, ConstantInt::get(context, APInt(64, 0)), "getflag-cmpne");
}

Value* setFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = createShlFolder(builder,one, position);

	Value* inverse_mask = builder.CreateNot(bit_position);

	
	Value* cleared_rflag = createAndFolder(builder,rflag_var, inverse_mask,"setflag2");

	
	Value* shifted_newValue = createShlFolder(builder,createZExtOrTruncFolder(builder,newValue, Type::getInt64Ty(context)), position, "flagsetweird");
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



void pushFlags(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, vector<Value*> value, string address) {
	auto rsp = GetRegisterValue(context, builder, ZYDIS_REGISTER_RSP);


	for (size_t i = 0; i < value.size(); i += 8) { 
		Value* byteVal = ConstantInt::get(Type::getInt8Ty(context), 0); 
		for (size_t j = 0; j < 8 && (i + j) < value.size(); ++j) {
			Value* flag = value[i + j]; 
			Value* extendedFlag = createZExtFolder(builder,flag, Type::getInt8Ty(context),"pushflag1");
			Value* shiftedFlag = createShlFolder(builder,extendedFlag, j,"pushflag2");
			byteVal = createOrFolder(builder, byteVal, shiftedFlag,"pushflagbyteval");
		}



		std::vector<Value*> indices;
		indices.push_back(rsp);
		Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPSTORE-" + address + "-");

		
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