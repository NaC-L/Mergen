#include "OperandUtils.h"
#include "GEPTracker.h"
#include "includes.h"
#include <llvm/IR/Constants.h>

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

// returns if a comes before b
bool comesBefore(Instruction* a, Instruction* b, DominatorTree& DT) {

  bool sameBlock =
      a->getParent() == b->getParent(); // if same block, use ->comesBefore,

  if (sameBlock) {
    return a->comesBefore(b); // if a comes before b, return true
  }
  // if "a"'s block dominates "b"'s block, "a" comes first.
  bool dominate = DT.properlyDominates(a->getParent(), b->getParent());
  return dominate;
}

using namespace llvm::PatternMatch;

Value* doPatternMatching(Instruction::BinaryOps I, Value* op0, Value* op1) {
  Value* X = nullptr;
  switch (I) {
  case Instruction::And: {
    // X & ~X
    // how the hell we remove this zext and truncs it looks horrible

    if ((match(op0, m_Not(m_Value(X))) && X == op1) ||
        (match(op1, m_Not(m_Value(X))) && X == op0) ||
        (match(op0, m_ZExt(m_Not(m_Value(X)))) &&
         match(op1, m_ZExt(m_Specific(X)))) ||
        (match(op1, m_ZExt(m_Not(m_Value(X)))) &&
         match(op0, m_ZExt(m_Specific(X)))) ||
        (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
         match(op1, m_Trunc(m_Specific(X)))) ||
        (match(op1, m_Trunc(m_Not(m_Value(X)))) &&
         match(op0, m_Trunc(m_Specific(X))))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), 0);
      return possibleSimplify;
    }
    // ~X & ~X

    if (match(op0, m_Not(m_Value(X))) && X == op1)
      return op0;

    break;
  }
  case Instruction::Xor: {
    // X ^ ~X
    if ((match(op0, m_Not(m_Value(X))) && X == op1) ||
        (match(op1, m_Not(m_Value(X))) && X == op0) ||
        (match(op0, m_ZExt(m_Not(m_Value(X)))) &&
         match(op1, m_ZExt(m_Specific(X)))) ||
        (match(op1, m_ZExt(m_Not(m_Value(X)))) &&
         match(op0, m_ZExt(m_Specific(X)))) ||
        (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
         match(op1, m_Trunc(m_Specific(X)))) ||
        (match(op1, m_Trunc(m_Not(m_Value(X)))) &&
         match(op0, m_Trunc(m_Specific(X))))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), -1);
      printvalue(possibleSimplify);
      return possibleSimplify;
    }
    if (match(op0, m_Specific(op1)) ||
        (match(op0, m_Trunc(m_Value(X))) &&
         match(op1, m_Trunc(m_Specific(X)))) ||
        (match(op0, m_ZExt(m_Value(X))) && match(op1, m_ZExt(m_Specific(X))))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), 0);
      printvalue(possibleSimplify);
      return possibleSimplify;
    }
    break;
  }
  default: {
    return nullptr;
  }
  }

  return nullptr;
}

KnownBits analyzeValueKnownBits(Value* value, const DataLayout& DL) {
  KnownBits knownBits(64);
  knownBits.resetAll();
  if (value->getType() == Type::getInt128Ty(value->getContext()))
    return knownBits;

  auto KB = computeKnownBits(value, DL);

  // BLAME
  if (KB.getBitWidth() < 64)
    (&KB)->zext(64);

  return KB;
}

Value* simplifyValue(Value* v, const DataLayout& DL) {

  if (!isa<Instruction>(v))
    return v;

  Instruction* inst = cast<Instruction>(v);

  /*
  shl al, cl
  where cl is bigger than 8, it just clears the al
  */

  SimplifyQuery SQ(DL, inst);
  if (auto vconstant = ConstantFoldInstruction(inst, DL)) {
    if (isa<PoisonValue>(vconstant)) // if poison it should be 0 for shifts,
                                     // can other operations generate poison
                                     // without a poison value anyways?
      return ConstantInt::get(v->getType(), 0);
    return vconstant;
  }

  if (auto vsimplified = simplifyInstruction(inst, SQ)) {

    if (isa<PoisonValue>(vsimplified)) // if poison it should be 0 for shifts,
                                       // can other operations generate poison
                                       // without a poison value anyways?
      return ConstantInt::get(v->getType(), 0);

    return vsimplified;
  }

  return v;
}

SolvedMemoryValue simplifyLoadValue(Value* v) {

  Instruction* inst = cast<Instruction>(v);
  Function& F = *inst->getFunction();

  llvm::IRBuilder<> builder(&*F.getEntryBlock().getFirstInsertionPt());
  auto LInst = cast<LoadInst>(v);
  auto GEPVal = LInst->getPointerOperand();

  if (!isa<GetElementPtrInst>(GEPVal))
    return SolvedMemoryValue(nullptr, Assumed);

  auto GEPInst = cast<GetElementPtrInst>(GEPVal);

  Value* pv = GEPInst->getPointerOperand();
  Value* idxv = GEPInst->getOperand(1);
  uint32_t byteCount = v->getType()->getIntegerBitWidth() / 8;

  printvalue(v) printvalue(pv) printvalue(idxv) printvalue2(byteCount);

  auto retVal = GEPStoreTracker::solveLoad(cast<LoadInst>(v), 0);

  printvalue(v);
  return retVal;
}

Value* simplifyValueLater(Value* v, const DataLayout& DL) {
  printvalue(v);
  if (!isa<Instruction>(v))
    return v;
  if (!isa<LoadInst>(v))
    return simplifyValue(v, DL);

  auto loadInst = cast<LoadInst>(v);
  printvalue(loadInst);
  auto GEP = loadInst->getOperand(loadInst->getNumOperands() - 1);
  printvalue(GEP);
  auto gepInst = cast<GetElementPtrInst>(GEP);
  auto effectiveAddress = gepInst->getOperand(gepInst->getNumOperands() - 1);
  printvalue(effectiveAddress);
  if (!isa<ConstantInt>(effectiveAddress)) {
    return v;
  }

  ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(effectiveAddress);
  if (!effectiveAddressInt)
    return nullptr;

  uint64_t addr = effectiveAddressInt->getZExtValue();

  // also the second case
  if (addr > 0 && addr < STACKP_VALUE) {
    auto SLV = simplifyLoadValue(v);
    if (SLV.val)
      return SLV.val;
  }

  unsigned byteSize = v->getType()->getIntegerBitWidth() / 8;

  APInt value;
  if (BinaryOperations::readMemory(addr, byteSize, value)) {
    Constant* newVal = ConstantInt::get(v->getType(), value);

    if (newVal)
      return newVal;
  }

  return v;
}
struct InstructionKey {
  unsigned opcode;
  Value* operand1;
  Value* operand2;
  Type* destType;

  bool operator==(const InstructionKey& other) const {
    return opcode == other.opcode && operand1 == other.operand1 &&
           operand2 == other.operand2 && destType == other.destType;
  }
};

struct InstructionKeyHash {
  std::size_t operator()(const InstructionKey& key) const {
    return std::hash<unsigned>()(key.opcode) ^
           std::hash<Value*>()(key.operand1) ^
           (key.operand2 ? std::hash<Value*>()(key.operand2) : 0) ^
           (key.destType ? std::hash<Type*>()(key.destType) : 0);
  }
};

class InstructionCache {
public:
  Value* getOrCreate(IRBuilder<>& builder, const InstructionKey& key,
                     const Twine& Name) {
    auto it = cache.find(key);
    if (it != cache.end()) {
      return it->second;
    }

    Value* newInstruction = nullptr;
    if (key.operand2) {
      // Binary instruction
      newInstruction =
          builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                              key.operand1, key.operand2, Name);
    } else if (key.destType) {
      // Cast instruction
      switch (key.opcode) {
      case Instruction::Trunc:
        newInstruction = builder.CreateTrunc(key.operand1, key.destType, Name);
        break;
      case Instruction::ZExt:
        newInstruction = builder.CreateZExt(key.operand1, key.destType, Name);
        break;
      case Instruction::SExt:
        newInstruction = builder.CreateSExt(key.operand1, key.destType, Name);
        break;
      // Add other cast operations as needed
      default:
        llvm_unreachable("Unsupported cast opcode");
      }
    } else {
      // Unary instruction
      switch (key.opcode) {
      case Instruction::Trunc:
        newInstruction =
            builder.CreateTrunc(key.operand1, key.operand1->getType(), Name);
        break;
      case Instruction::ZExt:
        newInstruction =
            builder.CreateZExt(key.operand1, key.operand1->getType(), Name);
        break;
      case Instruction::SExt:
        newInstruction =
            builder.CreateSExt(key.operand1, key.operand1->getType(), Name);
        break;
      // Add other unary operations as needed
      default:
        llvm_unreachable("Unsupported unary opcode");
      }
    }

    cache[key] = newInstruction;
    return newInstruction;
  }

private:
  std::unordered_map<InstructionKey, Value*, InstructionKeyHash> cache;
};

Value* createInstruction(IRBuilder<>& builder, unsigned opcode, Value* operand1,
                         Value* operand2, Type* destType, const Twine& Name) {
  static InstructionCache cache;
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  InstructionKey key = {opcode, operand1, operand2, destType};

  Value* newValue = cache.getOrCreate(builder, key, Name);
  return simplifyValue(newValue, DL);
}

Value* createSelectFolder(IRBuilder<>& builder, Value* C, Value* True,
                          Value* False, const Twine& Name) {
#ifdef TESTFOLDER
  if (auto* CConst = dyn_cast<Constant>(C)) {

    if (auto* CBool = dyn_cast<ConstantInt>(CConst)) {
      if (CBool->isOne()) {
        return True;
      } else if (CBool->isZero()) {
        return False;
      }
    }
  }
#endif
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  return simplifyValue(builder.CreateSelect(C, True, False, Name), DL);
}

Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {
#ifdef TESTFOLDER3

  if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (LHSConst->isZero())
      return RHS;
  }
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isZero())
      return LHS;
  }
#endif
  return createInstruction(builder, Instruction::Add, LHS, RHS, nullptr, Name);
}

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {
#ifdef TESTFOLDER4
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isZero())
      return LHS;
  }
#endif
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  return createInstruction(builder, Instruction::Sub, LHS, RHS, nullptr, Name);
}

Value* foldLShrKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {

  if (RHS.hasConflict() || LHS.hasConflict() || !RHS.isConstant() ||
      RHS.getBitWidth() > 64 || LHS.isUnknown() || LHS.getBitWidth() <= 1)
    return nullptr;

  APInt shiftAmount = RHS.getConstant();
  unsigned shiftSize = shiftAmount.getZExtValue();

  if (shiftSize >= LHS.getBitWidth())
    return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), 0);
  ;

  KnownBits result(LHS.getBitWidth());
  result.One = LHS.One.lshr(shiftSize);
  result.Zero = LHS.Zero.lshr(shiftSize) |
                APInt::getHighBitsSet(LHS.getBitWidth(), shiftSize);

  if (!(result.Zero | result.One).isAllOnes()) {
    return nullptr;
  }

  return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()),
                          result.getConstant());
}

Value* foldShlKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {
  if (RHS.hasConflict() || LHS.hasConflict() || !RHS.isConstant() ||
      RHS.getBitWidth() > 64 || LHS.isUnknown() || LHS.getBitWidth() <= 1)
    return nullptr;

  APInt shiftAmount = RHS.getConstant();
  unsigned shiftSize = shiftAmount.getZExtValue();

  if (shiftSize >= LHS.getBitWidth())
    return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()), 0);

  KnownBits result(LHS.getBitWidth());
  result.One = LHS.One.shl(shiftSize);
  result.Zero = LHS.Zero.shl(shiftSize) |
                APInt::getLowBitsSet(LHS.getBitWidth(), shiftSize);

  if (result.hasConflict() || !result.isConstant()) {
    return nullptr;
  }

  return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()),
                          result.getConstant());
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {

#ifdef TESTFOLDERshl

  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS))
      return ConstantInt::get(RHS->getType(), LHSConst->getZExtValue()
                                                  << RHSConst->getZExtValue());
    if (RHSConst->isZero())
      return LHS;
  }
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

  if (Value* knownBitsShl =
          foldShlKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
    return knownBitsShl;
  }

#endif

  return createInstruction(builder, Instruction::Shl, LHS, RHS, nullptr, Name);
}

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                        const Twine& Name) {

#ifdef TESTFOLDERshr

  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS))
      return ConstantInt::get(RHS->getType(), LHSConst->getZExtValue() >>
                                                  RHSConst->getZExtValue());
    if (RHSConst->isZero())
      return LHS;
  }

  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

  if (Value* knownBitsLshr =
          foldLShrKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
    // printvalue(knownBitsLshr)
    return knownBitsLshr;
  }

#endif

  return createInstruction(builder, Instruction::LShr, LHS, RHS, nullptr, Name);
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, uint64_t RHS,
                       const Twine& Name) {
  return createShlFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS),
                         Name);
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, APInt RHS,
                       const Twine& Name) {
  return createShlFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS),
                         Name);
}

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, uint64_t RHS,
                        const Twine& Name) {
  return createLShrFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS),
                          Name);
}
Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, APInt RHS,
                        const Twine& Name) {
  return createLShrFolder(builder, LHS, ConstantInt::get(LHS->getType(), RHS),
                          Name);
}

Value* foldOrKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {

  if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() ||
      RHS.isUnknown() || LHS.getBitWidth() != RHS.getBitWidth() ||
      !RHS.isConstant() || LHS.getBitWidth() <= 1 || RHS.getBitWidth() < 1 ||
      RHS.getBitWidth() > 64 || LHS.getBitWidth() > 64) {
    return nullptr;
  }

  KnownBits combined;
  combined.One = LHS.One | RHS.One;
  combined.Zero = LHS.Zero & RHS.Zero;

  if (!combined.isConstant() || combined.hasConflict()) {
    return nullptr;
  }

  APInt resultValue = combined.One;
  return ConstantInt::get(Type::getIntNTy(context, combined.getBitWidth()),
                          resultValue);
}

Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                      const Twine& Name) {
#ifdef TESTFOLDER5

  if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS))
      return ConstantInt::get(RHS->getType(), RHSConst->getZExtValue() |
                                                  LHSConst->getZExtValue());
    if (LHSConst->isZero())
      return RHS;
  }
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isZero())
      return LHS;
  }

  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);
  printvalue2(KnownLHS) printvalue2(KnownRHS);
  if (Value* knownBitsAnd =
          foldOrKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
    return knownBitsAnd;
  }
  if (Value* knownBitsAnd =
          foldOrKnownBits(builder.getContext(), KnownRHS, KnownLHS)) {
    return knownBitsAnd;
  }
#endif

  auto result =
      createInstruction(builder, Instruction::Or, LHS, RHS, nullptr, Name);
  KnownBits KnownResult = analyzeValueKnownBits(result, DL);
  printvalue2(KnownResult);
  return result;
}

Value* foldXorKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {

  if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() ||
      RHS.isUnknown() || !RHS.isConstant() ||
      LHS.getBitWidth() != RHS.getBitWidth() || RHS.getBitWidth() <= 1 ||
      LHS.getBitWidth() <= 1 || RHS.getBitWidth() > 64 ||
      LHS.getBitWidth() > 64) {
    return nullptr;
  }

  if (!((LHS.Zero | LHS.One) & RHS.One).eq(RHS.One)) {
    return nullptr;
  }
  APInt resultValue = LHS.One ^ RHS.One;

  return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()),
                          resultValue);
}

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {
#ifdef TESTFOLDER6

  if (LHS == RHS) {
    return ConstantInt::get(LHS->getType(), 0);
  }

  if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS))
      return ConstantInt::get(RHS->getType(), RHSConst->getZExtValue() ^
                                                  LHSConst->getZExtValue());
    if (LHSConst->isZero())
      return RHS;
  }
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isZero())
      return LHS;
  }

#endif
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

  if (auto V = foldXorKnownBits(builder.getContext(), KnownLHS, KnownRHS))
    return V;
  if (auto simplifiedByPM = doPatternMatching(Instruction::Xor, LHS, RHS))
    return simplifiedByPM;
  return createInstruction(builder, Instruction::Xor, LHS, RHS, nullptr, Name);
}

std::optional<bool> foldKnownBits(CmpInst::Predicate P, KnownBits LHS,
                                  KnownBits RHS) {

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
  default:
    return nullopt;
  }

  return nullopt;
}

Value* ICMPPatternMatcher(IRBuilder<>& builder, CmpInst::Predicate P,
                          Value* LHS, Value* RHS, const Twine& Name) {
  switch (P) {
  case CmpInst::ICMP_UGT: {
    // Check if LHS is the result of a call to @llvm.ctpop.i64
    if (match(RHS, m_SpecificInt(64))) {
      // Check if LHS is `and i64 %neg, 255`
      Value* Neg = nullptr;
      if (match(LHS, m_And(m_Value(Neg), m_SpecificInt(255)))) {
        // Check if `neg` is `sub nsw i64 0, %125`
        Value* CtpopResult = nullptr;
        if (match(Neg, m_Sub(m_Zero(), m_Value(CtpopResult)))) {
          // Check if `%125` is a call to `llvm.ctpop.i64`
          if (auto* CI = dyn_cast<CallInst>(CtpopResult)) {
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getIntrinsicID() == Intrinsic::ctpop) {
              Value* R8 = CI->getArgOperand(0);
              // Replace with: %isIndexInBound = icmp ne i64 %r8, 0
              auto* isIndexInBound =
                  builder.CreateICmpNE(R8, builder.getInt64(0), Name);
              return isIndexInBound;
            }
          }
        }
      }
    }
    break;
  }
  default: {
    return nullptr;
  }
  }
  return nullptr;
}

Value* createICMPFolder(IRBuilder<>& builder, CmpInst::Predicate P, Value* LHS,
                        Value* RHS, const Twine& Name) {
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

  if (std::optional<bool> v = foldKnownBits(P, KnownLHS, KnownRHS)) {
    return ConstantInt::get(Type::getInt1Ty(builder.getContext()), v.value());
  }
  printvalue2(KnownLHS) printvalue2(KnownRHS);
  printvalue(LHS) printvalue(RHS);
  if (auto patternCheck = ICMPPatternMatcher(builder, P, LHS, RHS, Name)) {
    printvalue(patternCheck);
    return patternCheck;
  }
  auto resultcmp = simplifyValue(builder.CreateICmp(P, LHS, RHS, Name), DL);
  return resultcmp;
}

Value* foldAndKnownBits(LLVMContext& context, KnownBits LHS, KnownBits RHS) {
  if (RHS.hasConflict() || LHS.hasConflict() || LHS.isUnknown() ||
      RHS.isUnknown() || !RHS.isConstant() ||
      LHS.getBitWidth() != RHS.getBitWidth() || RHS.getBitWidth() <= 1 ||
      LHS.getBitWidth() <= 1 || RHS.getBitWidth() > 64 ||
      LHS.getBitWidth() > 64) {
    return nullptr;
  }

  if (!((LHS.Zero | LHS.One) & RHS.One).eq(RHS.One)) {
    return nullptr;
  }
  APInt resultValue = LHS.One & RHS.One;

  return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()),
                          resultValue);
}

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {
#ifdef TESTFOLDER
  if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS))
      return ConstantInt::get(RHS->getType(), RHSConst->getZExtValue() &
                                                  LHSConst->getZExtValue());
    if (LHSConst->isZero())
      return ConstantInt::get(RHS->getType(), 0);
  }
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isZero())
      return ConstantInt::get(LHS->getType(), 0);
  }
  if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (LHSConst->isMinusOne())
      return RHS;
  }
  if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
    if (RHSConst->isMinusOne())
      return LHS;
  }

  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  KnownBits KnownLHS = analyzeValueKnownBits(LHS, DL);
  KnownBits KnownRHS = analyzeValueKnownBits(RHS, DL);

  if (Value* knownBitsAnd =
          foldAndKnownBits(builder.getContext(), KnownLHS, KnownRHS)) {
    printvalue(knownBitsAnd);
    return knownBitsAnd;
  }
  if (Value* knownBitsAnd =
          foldAndKnownBits(builder.getContext(), KnownRHS, KnownLHS)) {
    printvalue(knownBitsAnd);
    return knownBitsAnd;
  }

#endif
  if (auto sillyResult = doPatternMatching(Instruction::And, LHS, RHS)) {
    printvalue(sillyResult);
    return sillyResult;
  }
  return createInstruction(builder, Instruction::And, LHS, RHS, nullptr, Name);
}

// - probably not needed anymore
Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                         const Twine& Name) {
  Value* resulttrunc = builder.CreateTrunc(V, DestTy, Name);
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());

  KnownBits KnownLHS = analyzeValueKnownBits(V, DL);
  printvalue2(KnownLHS);
  KnownBits KnownTruncResult = analyzeValueKnownBits(resulttrunc, DL);
  printvalue2(KnownTruncResult);
  if (!KnownTruncResult.hasConflict() && KnownTruncResult.getBitWidth() > 1 &&
      KnownTruncResult.isConstant())
    return ConstantInt::get(DestTy, KnownTruncResult.getConstant());
  // TODO: CREATE A MAP FOR AVAILABLE TRUNCs/ZEXTs/SEXTs
  // WHY?
  // IF %y = trunc %x exists
  // we dont want to create %y2 = trunc %x
  // just use %y
  // so xor %y, %y2 => %y, %y => 0

  return simplifyValue(resulttrunc, DL);
}

Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                        const Twine& Name) {
  auto resultzext = builder.CreateZExt(V, DestTy, Name);
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER8

  KnownBits KnownRHS = analyzeValueKnownBits(resultzext, DL);
  if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
      KnownRHS.isConstant())
    return ConstantInt::get(DestTy, KnownRHS.getConstant());
#endif
  return simplifyValue(resultzext, DL);
}

Value* createZExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                               const Twine& Name) {
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createZExtFolder(builder, V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(builder, V, DestTy, Name);
  return V;
}

Value* createSExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                        const Twine& Name) {
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
    return ConstantInt::get(
        DestTy, ConstInt->getValue().sextOrTrunc(DestTy->getIntegerBitWidth()));
  }

  if (auto* SExtInsts = dyn_cast<SExtInst>(V)) {
    return builder.CreateSExt(SExtInsts->getOperand(0), DestTy, Name);
  }
#endif

  return builder.CreateSExt(V, DestTy, Name);
}

Value* createSExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                               const Twine& Name) {
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

RegisterMap Registers;
unordered_map<Flag, Value*> FlagList;

void Init_Flags(IRBuilder<>& builder) {
  LLVMContext& context = builder.getContext();
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

// ???
Value* setFlag(IRBuilder<>& builder, Flag flag, Value* newValue = nullptr) {
  LLVMContext& context = builder.getContext();
  newValue = createTruncFolder(builder, newValue, Type::getInt1Ty(context));
  printvalue2((int32_t)flag) printvalue(newValue);
  if (flag == FLAG_RESERVED1 || flag == FLAG_RESERVED5 || flag == FLAG_IF ||
      flag == FLAG_DF)
    return nullptr;

  return FlagList[flag] = newValue;
}
Value* getFlag(IRBuilder<>& builder, Flag flag) {
  if (FlagList[flag])
    return FlagList[flag];

  LLVMContext& context = builder.getContext();
  return ConstantInt::getSigned(Type::getInt1Ty(context), 0);
}

// for love of god this is so ugly
RegisterMap getRegisters() { return Registers; }
void setRegisters(RegisterMap newRegisters) { Registers = newRegisters; }

Value* memoryAlloc;
Value* TEB;
void initMemoryAlloc(Value* allocArg) { memoryAlloc = allocArg; }
Value* getMemory() { return memoryAlloc; }

// todo?
ReverseRegisterMap flipRegisterMap() {
  ReverseRegisterMap RevMap;
  for (const auto& pair : Registers) {
    RevMap[pair.second] = pair.first;
  }
  /*for (const auto& pair : FlagList) {
          RevMap[pair.second] = pair.first;
  }*/
  return RevMap;
}

RegisterMap InitRegisters(IRBuilder<>& builder, Function* function,
                          ZyanU64 rip) {

  int zydisRegister = ZYDIS_REGISTER_RAX;

  auto argEnd = function->arg_end();
  for (auto argIt = function->arg_begin(); argIt != argEnd; ++argIt) {

    Argument* arg = &*argIt;
    arg->setName(ZydisRegisterGetString((ZydisRegister)zydisRegister));

    if (std::next(argIt) == argEnd) {
      arg->setName("memory");
      memoryAlloc = arg;
    } else if (std::next(argIt, 2) == argEnd) {
      arg->setName("TEB");
      TEB = arg;
    } else {
      arg->setName(ZydisRegisterGetString((ZydisRegister)zydisRegister));
      Registers[(ZydisRegister)zydisRegister] = arg;
      zydisRegister++;
    }
  }

  Init_Flags(builder);

  LLVMContext& context = builder.getContext();

  auto zero = ConstantInt::getSigned(Type::getInt64Ty(context), 0);

  auto value =
      cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), rip));

  auto new_rip = createAddFolder(builder, zero, value);

  Registers[ZYDIS_REGISTER_RIP] = new_rip;

  auto stackvalue = cast<Value>(
      ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));
  auto new_stack_pointer = createAddFolder(builder, stackvalue, zero);

  Registers[ZYDIS_REGISTER_RSP] = new_stack_pointer;

  return Registers;
}

Value* GetValueFromHighByteRegister(IRBuilder<>& builder, int reg) {

  Value* fullRegisterValue = Registers[ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg)];

  Value* shiftedValue =
      createLShrFolder(builder, fullRegisterValue, 8, "highreg");

  Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
  Value* highByteValue = createAndFolder(builder, shiftedValue, FF, "highByte");

  return highByteValue;
}

void SetRFLAGSValue(IRBuilder<>& builder, Value* value) {
  LLVMContext& context = builder.getContext();
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    int shiftAmount = flag;
    Value* shiftedFlagValue = createLShrFolder(
        builder, value, ConstantInt::get(value->getType(), shiftAmount),
        "setflag");
    auto flagValue = createTruncFolder(builder, shiftedFlagValue,
                                       Type::getInt1Ty(context), "flagtrunc");

    setFlag(builder, (Flag)flag, flagValue);
  }
  return;
}

Value* GetRFLAGSValue(IRBuilder<>& builder) {
  LLVMContext& context = builder.getContext();
  Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0);
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    Value* flagValue = getFlag(builder, (Flag)flag);
    int shiftAmount = flag;
    Value* shiftedFlagValue = createShlFolder(
        builder,
        createZExtFolder(builder, flagValue, Type::getInt64Ty(context),
                         "createrflag1"),
        ConstantInt::get(Type::getInt64Ty(context), shiftAmount),
        "createrflag2");
    rflags = createOrFolder(builder, rflags, shiftedFlagValue, "creatingrflag");
  }
  return rflags;
}

Value* GetRegisterValue(IRBuilder<>& builder, int key) {

  if (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH ||
      key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH) {
    return GetValueFromHighByteRegister(builder, key);
  }

  int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
                   ? ZydisRegisterGetLargestEnclosing(
                         ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key)
                   : key;

  if (key == ZYDIS_REGISTER_RFLAGS || key == ZYDIS_REGISTER_EFLAGS) {
    return GetRFLAGSValue(builder);
  }

  /*
  if (Registers.find(newKey) == Registers.end()) {
          throw std::runtime_error("register not found"); exit(-1);
  }
  */

  return Registers[newKey];
}

Value* SetValueToHighByteRegister(IRBuilder<>& builder, int reg, Value* value) {
  LLVMContext& context = builder.getContext();
  int shiftValue = 8;

  int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
                                                    (ZydisRegister)reg);
  Value* fullRegisterValue = Registers[fullRegKey];

  Value* eightBitValue = createAndFolder(
      builder, value, ConstantInt::get(value->getType(), 0xFF), "eight-bit");
  Value* shiftedValue =
      createShlFolder(builder, eightBitValue,
                      ConstantInt::get(value->getType(), shiftValue), "shl");

  Value* mask =
      ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
  Value* clearedRegister =
      createAndFolder(builder, fullRegisterValue, mask, "clear-reg");

  shiftedValue =
      createZExtFolder(builder, shiftedValue, fullRegisterValue->getType());

  Value* newRegisterValue =
      createOrFolder(builder, clearedRegister, shiftedValue, "high_byte");

  return newRegisterValue;
}

Value* SetValueToSubRegister_8b(IRBuilder<>& builder, int reg, Value* value) {
  LLVMContext& context = builder.getContext();
  int fullRegKey = ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, static_cast<ZydisRegister>(reg));
  Value* fullRegisterValue = Registers[fullRegKey];
  fullRegisterValue = createZExtOrTruncFolder(builder, fullRegisterValue,
                                              Type::getInt64Ty(context));

  uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
  if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH ||
      reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
    mask = 0xFFFFFFFFFFFF00FFULL;
  } else {
    mask = 0xFFFFFFFFFFFFFF00ULL;
  }

  Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
  Value* extendedValue = createZExtFolder(
      builder, value, Type::getInt64Ty(context), "extendedValue");

  Value* maskedFullReg =
      createAndFolder(builder, fullRegisterValue, maskValue, "maskedreg");

  if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH ||
      reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
    extendedValue = createShlFolder(builder, extendedValue, 8, "shiftedValue");
  }

  Value* updatedReg =
      createOrFolder(builder, maskedFullReg, extendedValue, "newreg");

  printvalue(fullRegisterValue) printvalue(maskValue) printvalue(maskedFullReg)
      printvalue(extendedValue) printvalue(updatedReg);

  Registers[fullRegKey] = updatedReg;

  return updatedReg;
}

Value* SetValueToSubRegister_16b(IRBuilder<>& builder, int reg, Value* value) {

  int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
                                                    (ZydisRegister)reg);
  Value* fullRegisterValue = Registers[fullRegKey];

  Value* last4cleared =
      ConstantInt::get(fullRegisterValue->getType(), 0xFFFFFFFFFFFF0000);
  Value* maskedFullReg =
      createAndFolder(builder, fullRegisterValue, last4cleared, "maskedreg");
  value = createZExtFolder(builder, value, fullRegisterValue->getType());

  Value* updatedReg = createOrFolder(builder, maskedFullReg, value, "newreg");
  printvalue(updatedReg);
  return updatedReg;
}

void SetRegisterValue(int key, Value* value) {

  int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
                   ? ZydisRegisterGetLargestEnclosing(
                         ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key)
                   : key;
  Registers[newKey] = value;
  printvalue(Registers[newKey]);
}

void SetRegisterValue(IRBuilder<>& builder, int key, Value* value) {
  if ((key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH ||
       key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH)) {

    value = SetValueToSubRegister_8b(builder, key, value);
  }

  if (((key >= ZYDIS_REGISTER_R8B) && (key <= ZYDIS_REGISTER_R15B)) ||
      ((key >= ZYDIS_REGISTER_AL) && (key <= ZYDIS_REGISTER_BL)) ||
      ((key >= ZYDIS_REGISTER_SPL) && (key <= ZYDIS_REGISTER_DIL))) {

    value = SetValueToSubRegister_8b(builder, key, value);
  }

  if (((key >= ZYDIS_REGISTER_AX) && (key <= ZYDIS_REGISTER_R15W))) {
    value = SetValueToSubRegister_16b(builder, key, value);
  }

  if (key == ZYDIS_REGISTER_RFLAGS) {
    SetRFLAGSValue(builder, value);
    return;
  }

  int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
                   ? ZydisRegisterGetLargestEnclosing(
                         ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key)
                   : key;

  Registers[newKey] = value;
}

Value* GetEffectiveAddress(IRBuilder<>& builder, ZydisDecodedOperand& op,
                           int possiblesize) {
  LLVMContext& context = builder.getContext();

  Value* effectiveAddress = nullptr;

  Value* baseValue = nullptr;
  if (op.mem.base != ZYDIS_REGISTER_NONE) {
    baseValue = GetRegisterValue(builder, op.mem.base);
    baseValue = createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
    printvalue(baseValue);
  }

  Value* indexValue = nullptr;
  if (op.mem.index != ZYDIS_REGISTER_NONE) {
    indexValue = GetRegisterValue(builder, op.mem.index);

    indexValue =
        createZExtFolder(builder, indexValue, Type::getInt64Ty(context));
    printvalue(indexValue);
    if (op.mem.scale > 1) {
      Value* scaleValue =
          ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
      indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
    }
  }

  if (baseValue && indexValue) {
    effectiveAddress = createAddFolder(builder, baseValue, indexValue,
                                       "bvalue_indexvalue_set");
  } else if (baseValue) {
    effectiveAddress = baseValue;
  } else if (indexValue) {
    effectiveAddress = indexValue;
  } else {
    effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
  }

  if (op.mem.disp.value) {
    Value* dispValue =
        ConstantInt::get(Type::getInt64Ty(context), op.mem.disp.value);
    effectiveAddress =
        createAddFolder(builder, effectiveAddress, dispValue, "disp_set");
  }
  printvalue(effectiveAddress);
  return createZExtOrTruncFolder(builder, effectiveAddress,
                                 Type::getIntNTy(context, possiblesize));
}

Value* ConvertIntToPTR(IRBuilder<>& builder, Value* effectiveAddress) {

  LLVMContext& context = builder.getContext();
  std::vector<Value*> indices;
  indices.push_back(effectiveAddress);

  auto memoryOperand = memoryAlloc;
  //
  // if (segment == ZYDIS_REGISTER_GS)
  //     memoryOperand = TEB;

  Value* pointer =
      builder.CreateGEP(Type::getInt8Ty(context), memoryOperand, indices);
  return pointer;
}

Value* GetOperandValue(IRBuilder<>& builder, ZydisDecodedOperand& op,
                       int possiblesize, string address) {
  LLVMContext& context = builder.getContext();
  auto type = Type::getIntNTy(context, possiblesize);

  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    Value* value = GetRegisterValue(builder, op.reg.value);
    auto vtype = value->getType();
    if (isa<IntegerType>(vtype)) {
      auto typeBitWidth = dyn_cast<IntegerType>(vtype)->getBitWidth();
      if (typeBitWidth < 128)
        value = createZExtOrTruncFolder(builder, value, type, "trunc");
    }
    return value;
  }
  case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
    ConstantInt* val;
    if (op.imm.is_signed) {
      val = ConstantInt::getSigned(type, op.imm.value.s);
    } else {
      val = ConstantInt::get(context, APInt(possiblesize, op.imm.value.u)); // ?
    }
    return val;
  }
  case ZYDIS_OPERAND_TYPE_MEMORY: {

    Value* effectiveAddress = nullptr;

    Value* baseValue = nullptr;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
      baseValue = GetRegisterValue(builder, op.mem.base);
      baseValue =
          createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(builder, op.mem.index);
      indexValue =
          createZExtFolder(builder, indexValue, Type::getInt64Ty(context));
      printvalue(indexValue);
      if (op.mem.scale > 1) {
        Value* scaleValue =
            ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
        indexValue = builder.CreateMul(indexValue, scaleValue);
      }
    }

    if (baseValue && indexValue) {
      effectiveAddress =
          createAddFolder(builder, baseValue, indexValue, "bvalue_indexvalue");
    } else if (baseValue) {
      effectiveAddress = baseValue;
    } else if (indexValue) {
      effectiveAddress = indexValue;
    } else {
      effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
    }

    if (op.mem.disp.has_displacement) {
      Value* dispValue =
          ConstantInt::get(Type::getInt64Ty(context), (int)(op.mem.disp.value));
      effectiveAddress =
          createAddFolder(builder, effectiveAddress, dispValue, "memory_addr");
    }
    printvalue(effectiveAddress);

    Type* loadType = Type::getIntNTy(context, possiblesize);

    std::vector<Value*> indices;
    indices.push_back(effectiveAddress);
    Value* memoryOperand = memoryAlloc;
    if (op.mem.segment == ZYDIS_REGISTER_GS)
      memoryOperand = TEB;

    Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryOperand,
                                       indices, "GEPLoadxd-" + address + "-");

    auto retval =
        builder.CreateLoad(loadType, pointer, "Loadxd-" + address + "-");

    auto KBload = analyzeValueKnownBits(
        retval, retval->getFunction()->getParent()->getDataLayout());
    if (isa<ConstantInt>(effectiveAddress)) {
      ConstantInt* effectiveAddressInt =
          dyn_cast<ConstantInt>(effectiveAddress);
      if (!effectiveAddressInt)
        return nullptr;

      uint64_t addr = effectiveAddressInt->getZExtValue();

      unsigned byteSize = loadType->getIntegerBitWidth() / 8;

      APInt value(1, 0);
      SolvedMemoryValue solvedLoad = GEPStoreTracker::solveLoad(retval);
      if (solvedLoad.val) {
        if (solvedLoad.assumption == Real) {
          printvalue(solvedLoad.val);
          return solvedLoad.val;
        }
        if (BinaryOperations::readMemory(addr, byteSize, value)) {
          Constant* newVal_assumption = ConstantInt::get(loadType, value);
          printvalue(newVal_assumption);
          return newVal_assumption;
        }
        if (solvedLoad.val) {
          printvalue(solvedLoad.val);
          return solvedLoad.val;
        }
      }

      if (BinaryOperations::readMemory(addr, byteSize, value)) {

        Constant* newVal = ConstantInt::get(loadType, value);
        printvalue(newVal);
        return newVal;
      }
    }

    pointer = simplifyValue(
        pointer,
        builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

    printvalue(retval);

    return retval;
  }
  default: {
    throw std::runtime_error("operand type not implemented");
    exit(-1);
  }
  }
}

Value* SetOperandValue(IRBuilder<>& builder, ZydisDecodedOperand& op,
                       Value* value, string address) {
  LLVMContext& context = builder.getContext();
  value = simplifyValue(
      value,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    SetRegisterValue(builder, op.reg.value, value);
    return value;
    break;
  }
  case ZYDIS_OPERAND_TYPE_MEMORY: {

    Value* effectiveAddress = nullptr;

    Value* baseValue = nullptr;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
      baseValue = GetRegisterValue(builder, op.mem.base);
      baseValue =
          createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(builder, op.mem.index);
      indexValue =
          createZExtFolder(builder, indexValue, Type::getInt64Ty(context));
      printvalue(indexValue);
      if (op.mem.scale > 1) {
        Value* scaleValue =
            ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
        indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
      }
    }

    if (baseValue && indexValue) {
      effectiveAddress = createAddFolder(builder, baseValue, indexValue,
                                         "bvalue_indexvalue_set");
    } else if (baseValue) {
      effectiveAddress = baseValue;
    } else if (indexValue) {
      effectiveAddress = indexValue;
    } else {
      effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
    }

    if (op.mem.disp.value) {
      Value* dispValue =
          ConstantInt::get(Type::getInt64Ty(context), op.mem.disp.value);
      effectiveAddress =
          createAddFolder(builder, effectiveAddress, dispValue, "disp_set");
    }

    std::vector<Value*> indices;
    indices.push_back(effectiveAddress);

    auto memoryOperand = memoryAlloc;
    if (op.mem.segment == ZYDIS_REGISTER_GS)
      memoryOperand = TEB;

    Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryOperand,
                                       indices, "GEPSTORE-" + address + "-");

    pointer = simplifyValue(
        pointer,
        builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

    Value* store = builder.CreateStore(value, pointer);

    printvalue(effectiveAddress) printvalue(pointer);
    // if effectiveAddress is not pointing at stack, its probably self
    // modifying code if effectiveAddress and value is consant we can
    // say its a self modifying code and modify the binary

    GEPStoreTracker::insertMemoryOp(cast<StoreInst>(store));

    return store;
  } break;

  default: {
    throw std::runtime_error("operand type not implemented");
    exit(-1);
    return nullptr;
  }
  }
}

Value* getMemoryFromValue(IRBuilder<>& builder, Value* value) {
  LLVMContext& context = builder.getContext();

  std::vector<Value*> indices;
  indices.push_back(value);

  Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,
                                     indices, "GEPSTOREVALUE");

  return pointer;
}

// delete
Value* getFlag2(IRBuilder<>& builder, Flag flag) {
  LLVMContext& context = builder.getContext();
  Value* rflag_var = GetRegisterValue(builder, ZYDIS_REGISTER_RFLAGS);
  Value* position = ConstantInt::get(context, APInt(64, flag));

  Value* one = ConstantInt::get(context, APInt(64, 1));
  Value* bit_position = createShlFolder(builder, one, position, "getflag-shl");

  Value* and_result =
      createAndFolder(builder, rflag_var, bit_position, "getflag-and");
  return builder.CreateICmpNE(
      and_result, ConstantInt::get(context, APInt(64, 0)), "getflag-cmpne");
}

Value* setFlag2(IRBuilder<>& builder, Flag flag, Value* newValue) {
  LLVMContext& context = builder.getContext();
  Value* rflag_var = GetRegisterValue(builder, ZYDIS_REGISTER_RFLAGS);
  Value* position = ConstantInt::get(context, APInt(64, flag));

  Value* one = ConstantInt::get(context, APInt(64, 1));
  Value* bit_position = createShlFolder(builder, one, position);

  Value* inverse_mask = builder.CreateNot(bit_position);

  Value* cleared_rflag =
      createAndFolder(builder, rflag_var, inverse_mask, "setflag2");

  Value* shifted_newValue = createShlFolder(
      builder,
      createZExtOrTruncFolder(builder, newValue, Type::getInt64Ty(context)),
      position, "flagsetweird");
  shifted_newValue =
      createOrFolder(builder, cleared_rflag, shifted_newValue, "setflag-or");
  SetRegisterValue(builder, ZYDIS_REGISTER_RFLAGS, shifted_newValue);
  return shifted_newValue;
}

vector<Value*> GetRFLAGS(IRBuilder<>& builder) {
  vector<Value*> rflags;
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    rflags.push_back(getFlag(builder, (Flag)flag));
  }
  return rflags;
}

void pushFlags(IRBuilder<>& builder, vector<Value*> value, string address) {
  LLVMContext& context = builder.getContext();

  auto rsp = GetRegisterValue(builder, ZYDIS_REGISTER_RSP);

  for (size_t i = 0; i < value.size(); i += 8) {
    Value* byteVal = ConstantInt::get(Type::getInt8Ty(context), 0);
    for (size_t j = 0; j < 8 && (i + j) < value.size(); ++j) {
      Value* flag = value[i + j];
      Value* extendedFlag = createZExtFolder(
          builder, flag, Type::getInt8Ty(context), "pushflag1");
      Value* shiftedFlag =
          createShlFolder(builder, extendedFlag, j, "pushflag2");
      byteVal =
          createOrFolder(builder, byteVal, shiftedFlag, "pushflagbyteval");
    }

    std::vector<Value*> indices;
    indices.push_back(rsp);
    Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,
                                       indices, "GEPSTORE-" + address + "-");

    auto store = builder.CreateStore(byteVal, pointer, "storebyte");

    printvalue(rsp) printvalue(pointer) printvalue(byteVal) printvalue(store);

    GEPStoreTracker::insertMemoryOp(cast<StoreInst>(store));
    rsp = createAddFolder(builder, rsp, ConstantInt::get(rsp->getType(), 1));
  }
}

// return [rsp], rsp+=8
Value* popStack(IRBuilder<>& builder) {
  LLVMContext& context = builder.getContext();
  auto rsp = GetRegisterValue(builder, ZYDIS_REGISTER_RSP);
  // should we get a address calculator function, do we need that?

  std::vector<Value*> indices;
  indices.push_back(rsp);

  Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,
                                     indices, "GEPLoadPOPStack--");

  auto loadType = Type::getInt64Ty(context);
  auto returnValue = builder.CreateLoad(loadType, pointer, "PopStack-");

  auto CI = ConstantInt::get(rsp->getType(), 8);
  SetRegisterValue(ZYDIS_REGISTER_RSP, createAddFolder(builder, rsp, CI));

  if (isa<ConstantInt>(rsp)) {
    ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(rsp);
    if (!effectiveAddressInt)
      return nullptr;

    uint64_t addr = effectiveAddressInt->getZExtValue();

    unsigned byteSize = loadType->getBitWidth() / 8;

    APInt value(1, 0);
    SolvedMemoryValue solvedLoad = GEPStoreTracker::solveLoad(returnValue);
    if (solvedLoad.val) {
      if (solvedLoad.assumption == Real)
        return solvedLoad.val;

      if (BinaryOperations::readMemory(addr, byteSize, value)) {
        Constant* newVal = ConstantInt::get(loadType, value);
        printvalue(newVal);
        return newVal;
      }
      if (solvedLoad.val)
        return solvedLoad.val;
    }
  }

  return returnValue;
}