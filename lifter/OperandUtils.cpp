#include "OperandUtils.h"
#include "GEPTracker.h"
#include "includes.h"
#include "lifterClass.h"
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/KnownBits.h>

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

using namespace PatternMatch;

static void findAffectedValues(Value* Cond, SmallVectorImpl<Value*>& Affected) {
  auto AddAffected = [&Affected](Value* V) {
    if (isa<Argument>(V) || isa<GlobalValue>(V)) {
      Affected.push_back(V);
    } else if (auto* I = dyn_cast<Instruction>(V)) {
      Affected.push_back(I);

      // Peek through unary operators to find the source of the condition.

      Value* Op;
      if (match(I, m_PtrToInt(m_Value(Op)))) {
        if (isa<Instruction>(Op) || isa<Argument>(Op) && Op->hasNUsesOrMore(1))
          Affected.push_back(Op);
      }
    }
  };

  ICmpInst::Predicate Pred;
  Value* A;
  if (match(Cond, m_ICmp(Pred, m_Value(A), m_Constant()))) {
    AddAffected(A);

    if (ICmpInst::isEquality(Pred)) {
      Value* X;
      // (X & C) or (X | C) or (X ^ C).
      // (X << C) or (X >>_s C) or (X >>_u C).
      if (match(A, m_BitwiseLogic(m_Value(X), m_ConstantInt())) ||
          match(A, m_Shift(m_Value(X), m_ConstantInt())))
        AddAffected(X);
    } else {
      Value* X;
      // Handle (A + C1) u< C2, which is the canonical form of A > C3 && A < C4.
      if (match(A, m_Add(m_Value(X), m_ConstantInt())))
        AddAffected(X);
    }
  }
}
DomConditionCache* DC;
unsigned long BIlistsize = 0;
namespace GetSimplifyQuery {

  vector<BranchInst*> BIlist;
  void RegisterBranch(BranchInst* BI) {
    //
    BIlist.push_back(BI);
  }
  unsigned int instct = 0;
  SimplifyQuery* cachedquery;

  SimplifyQuery createSimplifyQuery(Function* fncv, Instruction* Inst) {
    static Function* fnc = fncv;
    GEPStoreTracker::updateDomTree(*fnc);
    auto DT = GEPStoreTracker::getDomTree();
    auto DL = fnc->getParent()->getDataLayout();
    static TargetLibraryInfoImpl TLIImpl(
        Triple(fnc->getParent()->getTargetTriple()));
    static TargetLibraryInfo TLI(TLIImpl);
    if (BIlist.size() != BIlistsize) {
      BIlistsize = BIlist.size();
      DC = new DomConditionCache();

      for (auto BI : BIlist) {

        DC->registerBranch(BI);
        SmallVector<Value*, 16> Affected;
        findAffectedValues(BI->getCondition(), Affected);
        for (auto affectedvalues : Affected) {
          printvalue(affectedvalues);
        }
      }
    }

    SimplifyQuery SQ(DL, &TLI, DT, nullptr, Inst, true, true, DC);

    return SQ;
  }

} // namespace GetSimplifyQuery

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
  Value* Y = nullptr;
  Value* Z = nullptr;

  switch (I) {
  case Instruction::Add:
  case Instruction::Or: {
    Value *Z = nullptr, *A = nullptr, *B = nullptr, *C = nullptr;

    // Match (~A & B) | (A & C)
    if ((match(op0, m_And(m_Not(m_Value(X)), m_Value(B))) &&
         match(op1, m_And(m_Value(X), m_Value(C)))) ||
        (match(op1, m_And(m_Not(m_Value(X)), m_Value(B))) &&
         match(op0, m_And(m_Value(X), m_Value(C))))) {
      // This matches (~A & B) | (A & C)
      // Simplify to A ? C : B

      // X is ( max(v) - v)
      printvalue(X);
      printvalue(B);
      printvalue(C);
      if (auto X_inst = dyn_cast<Instruction>(X)) {
        auto pv = GEPStoreTracker::computePossibleValues(X_inst);
        if (pv.size() == 2) {
          // check if pv is 0, -1

          IRBuilder<> builder(cast<Instruction>(op0));
          return createSelectFolder(builder, X, C, B, "selectEZ");
        }
      }

      // printvalue2(tryCompute.getMinValue()); if 0
      // printvalue2(tryCompute.getMaxValue()); if -1
      // do the simplfiication
    }
    break;
  }
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
    Value* A = nullptr;
    Value* B = nullptr;
    Value* C = nullptr;
    Value* D = nullptr;
    // not
    if (match(op1, m_SpecificInt(-1)) &&
        match(op0, m_Or(m_Value(A), m_Value(B)))) {
      IRBuilder<> builder(cast<Instruction>(op0));
      Constant* constant_v = nullptr;
      if (match(A, m_Not(m_Value(C))) && match(B, m_Constant(constant_v))) {
        // ~(~a | b)
        // simplify to
        // a & ~b
        printvalue(C);
        return createAndFolder(
            builder, C,
            createXorFolder(builder, constant_v,
                            Constant::getAllOnesValue(constant_v->getType())),
            "not-PConst-");
      }

      if (match(A, m_Value(C)) && match(B, m_Constant(constant_v))) {
        // ~(a | b(ci))
        // simplify to
        // ~a & ~b
        printvalue(C);
        return createAndFolder(
            builder,
            createXorFolder(builder, C, Constant::getAllOnesValue(C->getType()),
                            "not_v"),
            createXorFolder(builder, constant_v,
                            Constant::getAllOnesValue(constant_v->getType())),
            "not-PConst2-");
      }

      if (match(A, m_Not(m_Value(C))) && match(B, m_Not(m_Value(D)))) {
        // ~(~a | ~b)
        // simplify to
        // a & b
        printvalue(C);
        printvalue(D);
        return createAndFolder(builder, C, D, "not-P1-");
      }

      if (match(A, m_Not(m_Value(C)))) {
        // ~(~a | b)
        // simplify to
        // a & ~b
        printvalue(C);
        return createAndFolder(
            builder,
            createXorFolder(builder, B, Constant::getAllOnesValue(B->getType()),
                            "not-p2A-"),
            C, "not-P2-");
      }

      if (match(B, m_Not(m_Value(C)))) {
        // ~(a | ~b)
        // simplify to
        // ~a & b
        printvalue(C);
        return createAndFolder(
            builder,
            createXorFolder(builder, C, Constant::getAllOnesValue(C->getType()),
                            "not-p3A-"),
            B, "not-p3-");
      }

      printvalue(A);
      printvalue(B);
    }

    break;
  }

  default: {
    return nullptr;
  }
  }

  return nullptr;
}

KnownBits analyzeValueKnownBits(Value* value, Instruction* ctxI) {

  KnownBits knownBits(64);
  knownBits.resetAll();
  if (value->getType() == Type::getInt128Ty(value->getContext()))
    return knownBits;

  if (auto CIv = dyn_cast<ConstantInt>(value)) {
    return KnownBits::makeConstant(APInt(64, CIv->getZExtValue(), false));
  }
  auto SQ = GetSimplifyQuery::createSimplifyQuery(
      ctxI->getParent()->getParent(), ctxI);

  computeKnownBits(value, knownBits, 0, SQ);

  return knownBits;
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
  if (inst->getOpcode() == Instruction::Add) {
    auto testsimp = (simplifyBinOp(inst->getOpcode(), inst->getOperand(0),
                                   inst->getOperand(1), SQ));
    if (testsimp)
      printvalue(testsimp);
  }

  return v;
}

Value* simplifyLoadValue(Value* v) {

  Instruction* inst = cast<Instruction>(v);
  Function& F = *inst->getFunction();

  llvm::IRBuilder<> builder(&*F.getEntryBlock().getFirstInsertionPt());
  auto LInst = cast<LoadInst>(v);
  auto GEPVal = LInst->getPointerOperand();

  if (!isa<GetElementPtrInst>(GEPVal))
    return nullptr;

  auto GEPInst = cast<GetElementPtrInst>(GEPVal);

  Value* pv = GEPInst->getPointerOperand();
  Value* idxv = GEPInst->getOperand(1);
  uint32_t byteCount = v->getType()->getIntegerBitWidth() / 8;

  printvalue(v) printvalue(pv) printvalue(idxv) printvalue2(byteCount);

  auto retVal = GEPStoreTracker::solveLoad(cast<LoadInst>(v));

  printvalue(v);
  return retVal;
}

struct InstructionKey {
  unsigned opcode;
  bool cast;
  Value* operand1;
  union {
    Value* operand2;
    Type* destType;
  };

  InstructionKey(unsigned opcode, Value* operand1, Value* operand2)
      : opcode(opcode), cast(0), operand1(operand1), operand2(operand2){};

  InstructionKey(unsigned opcode, Value* operand1, Type* destType)
      : opcode(opcode), cast(1), operand1(operand1), destType(destType){};

  bool operator==(const InstructionKey& other) const {
    if (cast != other.cast)
      return false;
    if (cast) {
      return opcode == other.opcode && operand1 == other.operand1 &&
             destType == other.destType;
    } else {
      return opcode == other.opcode && operand1 == other.operand1 &&
             operand2 == other.operand2;
    }
  }
};

struct InstructionKeyHash {
  uint64_t operator()(const InstructionKey& key) const {
    uint64_t h1 = std::hash<unsigned>()(key.opcode);
    uint64_t h2 = reinterpret_cast<uint64_t>(key.operand1);
    uint64_t h3 = reinterpret_cast<uint64_t>(key.operand2);
    return h1 ^ (h2 << 1) ^ (h3 << 2);
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

    if (key.cast == 0) {
      printvalue2(key.opcode);
      printvalue2(key.cast);
      printvalue(key.operand1);
      printvalue(key.operand2);
      // Binary instruction
      if (auto select_inst = dyn_cast<SelectInst>(key.operand1)) {
        printvalue2(
            analyzeValueKnownBits(select_inst->getCondition(), select_inst));
        if (isa<ConstantInt>(key.operand2))
          return createSelectFolder(
              builder, select_inst->getCondition(),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getTrueValue(), key.operand2),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getFalseValue(), key.operand2),
              "lola-");
      }

      if (auto select_inst = dyn_cast<SelectInst>(key.operand2)) {
        printvalue2(
            analyzeValueKnownBits(select_inst->getCondition(), select_inst));
        if (isa<ConstantInt>(key.operand1))
          return createSelectFolder(
              builder, select_inst->getCondition(),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode), key.operand1,
                  select_inst->getTrueValue()),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode), key.operand1,
                  select_inst->getFalseValue()),
              "lolb-");
      }
      Value *select_inst1, *cnd1, *lhs1, *rhs1;
      if (match(key.operand1,
                m_TruncOrSelf(
                    m_Select(m_Value(cnd1), m_Value(lhs1), m_Value(rhs1))))) {
        if (auto select_inst = dyn_cast<SelectInst>(key.operand2))
          if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                  // if inversed
            return createSelectFolder(
                builder, select_inst->getCondition(),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getTrueValue(), lhs1),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getFalseValue(), rhs1),
                "lol2-");
      }

      else if (match(key.operand1,
                     m_ZExtOrSExtOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                                 m_Value(rhs1))))) {
        if (auto select_inst = dyn_cast<SelectInst>(key.operand2))
          if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                  // if inversed
            return createSelectFolder(
                builder, select_inst->getCondition(),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getTrueValue(), lhs1),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getFalseValue(), rhs1),
                "lol2-");
      }

      Value *select_inst2, *cnd, *lhs, *rhs;
      if (match(key.operand2, m_TruncOrSelf(m_Select(m_Value(cnd), m_Value(lhs),
                                                     m_Value(rhs))))) {
        if (auto select_inst = dyn_cast<SelectInst>(key.operand1))
          if (select_inst && cnd == select_inst->getCondition()) // also check
                                                                 // if inversed
            return createSelectFolder(
                builder, select_inst->getCondition(),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getTrueValue(), lhs),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getFalseValue(), rhs),
                "lol2-");
      } else if (match(key.operand2,
                       m_ZExtOrSExtOrSelf(m_Select(m_Value(cnd), m_Value(lhs),
                                                   m_Value(rhs))))) {
        if (auto select_inst = dyn_cast<SelectInst>(key.operand1))
          if (select_inst && cnd == select_inst->getCondition()) // also check
                                                                 // if inversed
            return createSelectFolder(
                builder, select_inst->getCondition(),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getTrueValue(), lhs),
                builder.CreateBinOp(
                    static_cast<Instruction::BinaryOps>(key.opcode),
                    select_inst->getFalseValue(), rhs),
                "lol2-");
      }
      newInstruction =
          builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                              key.operand1, key.operand2, Name);
    } else if (key.cast) {
      // Cast instruction
      switch (key.opcode) {

      case Instruction::Trunc:
      case Instruction::ZExt:
      case Instruction::SExt:
        printvalue(key.operand1);
        if (auto select_inst = dyn_cast<SelectInst>(key.operand1)) {
          return createSelectFolder(
              builder, select_inst->getCondition(),
              builder.CreateCast(static_cast<Instruction::CastOps>(key.opcode),
                                 select_inst->getTrueValue(), key.destType),
              builder.CreateCast(static_cast<Instruction::CastOps>(key.opcode),
                                 select_inst->getFalseValue(), key.destType),
              "lol-");
        }

        newInstruction =
            builder.CreateCast(static_cast<Instruction::CastOps>(key.opcode),
                               key.operand1, key.destType);
        break;
      // Add other cast operations as needed
      default:
        llvm_unreachable("Unsupported cast opcode");
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

  InstructionKey* key;
  if (destType)
    key = new InstructionKey(opcode, operand1, destType);
  else
    key = new InstructionKey(opcode, operand1, operand2);

  // cache trolls us for different branch
  Value* newValue = cache.getOrCreate(builder, *key, Name);

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

KnownBits computeKnownBitsFromOperation(KnownBits vv1, KnownBits vv2,
                                        Instruction::BinaryOps opcode) {

  if (opcode >= Instruction::Shl && opcode <= Instruction::AShr) {
    auto ugt_result = KnownBits::ugt(
        vv2,
        KnownBits::makeConstant(APInt(vv1.getBitWidth(), vv1.getBitWidth())));
    if (ugt_result.has_value() &&
        ugt_result.value()) { // has value and value == 1
      printvalue2(ugt_result.value());
      return KnownBits::makeConstant(APInt(vv1.getBitWidth(), 0));
    }
  }

  switch (opcode) {
  case Instruction::Add: {
    return KnownBits::computeForAddSub(1, 0, vv1, vv2);
    break;
  }
  case Instruction::Sub: {
    return KnownBits::computeForAddSub(0, 0, vv1, vv2);
    break;
  }
  case Instruction::Mul: {
    return KnownBits::mul(vv1, vv2);
    break;
  }
  case Instruction::LShr: {
    return KnownBits::lshr(vv1, vv2);
    break;
  }
  case Instruction::AShr: {
    return KnownBits::ashr(vv1, vv2);
    break;
  }
  case Instruction::Shl: {
    return KnownBits::shl(vv1, vv2);
    break;
  }
  case Instruction::UDiv: {
    if (!vv2.isZero()) {
      return (KnownBits::udiv(vv1, vv2));
    }
    break;
  }
  case Instruction::URem: {
    return KnownBits::urem(vv1, vv2);
    break;
  }
  case Instruction::SDiv: {
    if (!vv2.isZero()) {
      return KnownBits::sdiv(vv1, vv2);
    }
    break;
  }
  case Instruction::SRem: {
    return KnownBits::srem(vv1, vv2);
    break;
  }
  case Instruction::And: {
    return (vv1 & vv2);
    break;
  }
  case Instruction::Or: {
    return (vv1 | vv2);
    break;
  }
  case Instruction::Xor: {
    return (vv1 ^ vv2);
    break;
  }

  default:
    outs() << "\n : " << opcode;
    outs().flush();
    llvm_unreachable_internal(
        "Unsupported operation in calculatePossibleValues.\n");
    break;
  }
  /*
  case Instruction::ICmp: {
     KnownBits kb(64);
     kb.setAllOnes();
     kb.setAllZero();
     kb.One ^= 1;
     kb.Zero ^= 1;
     switch (cast<ICmpInst>(inst)->getPredicate()) {
     case llvm::CmpInst::ICMP_EQ: {
       auto idk = KnownBits::eq(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_NE: {
       auto idk = KnownBits::eq(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SLE: {
       auto idk = KnownBits::sle(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SLT: {
       auto idk = KnownBits::slt(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_ULE: {
       auto idk = KnownBits::ule(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_ULT: {
       auto idk = KnownBits::ult(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SGE: {
       auto idk = KnownBits::sge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SGT: {
       auto idk = KnownBits::sgt(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_UGE: {
       auto idk = KnownBits::uge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_UGT: {
       auto idk = KnownBits::uge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     default: {
       outs() << "\n : " << cast<ICmpInst>(inst)->getPredicate();
       outs().flush();
       llvm_unreachable_internal(
           "Unsupported operation in calculatePossibleValues ICMP.\n");
       break;
     }
     }
     break;
   }
  */
  return KnownBits(0); // never reach
}

Value* folderBinOps(IRBuilder<>& builder, Value* LHS, Value* RHS,
                    const Twine& Name, Instruction::BinaryOps opcode) {
  // ideally we go cheaper to more expensive

  // this part will eliminate unneccesary operations
  switch (opcode) {
    // shifts also should return 0 if shift is bigger than x's bitwidth
  case Instruction::Shl:    // x >> 0 = x , 0 >> x = 0
  case Instruction::LShr:   // x << 0 = x , 0 << x = 0
  case Instruction::AShr: { // x << 0 = x , 0 << x = 0

    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return LHS;
    }

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return LHS;

      if (RHSConst->getZExtValue() > LHS->getType()->getIntegerBitWidth()) {
        return builder.getIntN(LHS->getType()->getIntegerBitWidth(), 0);
      }
    }

    break;
  }
  case Instruction::Xor:   // x ^ 0 = x , 0 ^ x = 0
  case Instruction::Add: { // x + 0 = x , 0 + x = 0

    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return RHS;
    }

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return LHS;

      if (opcode >= Instruction::Shl && opcode <= Instruction::AShr &&
          RHSConst->getZExtValue() > LHS->getType()->getIntegerBitWidth()) {
        return builder.getIntN(LHS->getType()->getIntegerBitWidth(), 0);
      }
    }

    break;
  }
  case Instruction::Sub: {

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return LHS;
    }
    break;
  }
  case Instruction::Or: {
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return RHS;
      if (LHSConst->isMinusOne())
        return LHS;
    }
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return LHS;
      if (RHSConst->isMinusOne())
        return RHS;
    }
    break;
  }
  case Instruction::And: {
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return builder.getIntN(LHSConst->getBitWidth(), 0);
      if (LHSConst->isMinusOne())
        return RHS;
    }
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return builder.getIntN(RHSConst->getBitWidth(), 0);
      if (RHSConst->isMinusOne())
        return LHS;
    }
    break;
  }
  }
  // this part analyses if we can simplify the instruction
  if (auto simplifiedByPM = doPatternMatching(opcode, LHS, RHS))
    return simplifiedByPM;

  auto inst = createInstruction(builder, opcode, LHS, RHS, nullptr, Name);

  // knownbits is recursive, and goes back 5 instructions, ideally it would be
  // not recursive and store the info for all values
  // until then, we just calculate it ourselves

  // we can just swap analyzeValueKnownBits with something else later down the
  // road
  auto LHSKB = analyzeValueKnownBits(LHS, dyn_cast<Instruction>(inst));
  auto RHSKB = analyzeValueKnownBits(RHS, dyn_cast<Instruction>(inst));
  printvalue2(LHSKB);
  printvalue2(RHSKB);

  auto computedBits = computeKnownBitsFromOperation(LHSKB, RHSKB, opcode);
  if (computedBits.isConstant() && !computedBits.hasConflict())
    return builder.getIntN(LHS->getType()->getIntegerBitWidth(),
                           computedBits.getConstant().getZExtValue());

  return inst;
}

Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {

  return folderBinOps(builder, LHS, RHS, Name, Instruction::Add);
}

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {

  return folderBinOps(builder, LHS, RHS, Name, Instruction::Sub);
}

Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                      const Twine& Name) {

  return folderBinOps(builder, LHS, RHS, Name, Instruction::Or);
}

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {

  return folderBinOps(builder, LHS, RHS, Name, Instruction::Xor);
}

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {

  return folderBinOps(builder, LHS, RHS, Name, Instruction::And);
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

  KnownBits result = KnownBits::shl(LHS, RHS);

  if (result.hasConflict() || !result.isConstant()) {
    return nullptr;
  }

  return ConstantInt::get(Type::getIntNTy(context, LHS.getBitWidth()),
                          result.getConstant());
}

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name) {
  return folderBinOps(builder, LHS, RHS, Name, Instruction::Shl);
}

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                        const Twine& Name) {
  return folderBinOps(builder, LHS, RHS, Name, Instruction::LShr);
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
  if (auto SI = dyn_cast<SelectInst>(LHS)) {
    if (RHS == SI->getTrueValue())
      return SI->getCondition();
    // do stuff
  }
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
    break;
  }
  }
  // c = add a, b
  // cmp x, c, 0
  // =>
  // cmp x, a, -b

  // lhs is a bin op

  return nullptr;
}

Value* createICMPFolder(IRBuilder<>& builder, CmpInst::Predicate P, Value* LHS,
                        Value* RHS, const Twine& Name) {

  auto result = builder.CreateICmp(P, LHS, RHS, Name);

  if (auto ctxI = dyn_cast<Instruction>(result)) {

    KnownBits KnownLHS = analyzeValueKnownBits(LHS, ctxI);
    KnownBits KnownRHS = analyzeValueKnownBits(RHS, ctxI);

    if (std::optional<bool> v = foldKnownBits(P, KnownLHS, KnownRHS)) {
      return ConstantInt::get(Type::getInt1Ty(builder.getContext()), v.value());
    }
    printvalue2(KnownLHS) printvalue2(KnownRHS);
  }

  if (auto patternCheck = ICMPPatternMatcher(builder, P, LHS, RHS, Name)) {
    printvalue(patternCheck);
    return patternCheck;
  }

  return result;
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

// - probably not needed anymore
Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                         const Twine& Name) {
  Value* result =
      createInstruction(builder, Instruction::Trunc, V, nullptr, DestTy, Name);

  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
  if (auto ctxI = dyn_cast<Instruction>(result)) {

    KnownBits KnownTruncResult = analyzeValueKnownBits(result, ctxI);
    printvalue2(KnownTruncResult);
    if (!KnownTruncResult.hasConflict() && KnownTruncResult.getBitWidth() > 1 &&
        KnownTruncResult.isConstant())
      return ConstantInt::get(DestTy, KnownTruncResult.getConstant());
  }
  // TODO: CREATE A MAP FOR AVAILABLE TRUNCs/ZEXTs/SEXTs
  // WHY?
  // IF %y = trunc %x exists
  // we dont want to create %y2 = trunc %x
  // just use %y
  // so xor %y, %y2 => %y, %y => 0

  return simplifyValue(result, DL);
}

Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                        const Twine& Name) {
  auto result =
      createInstruction(builder, Instruction::ZExt, V, nullptr, DestTy, Name);
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return simplifyValue(result, DL);
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
  auto result =
      createInstruction(builder, Instruction::SExt, V, nullptr, DestTy, Name);
  DataLayout DL(builder.GetInsertBlock()->getParent()->getParent());
#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return simplifyValue(result, DL);
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

void lifterClass::Init_Flags() {
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
Value* lifterClass::setFlag(Flag flag, Value* newValue) {
  LLVMContext& context = builder.getContext();
  newValue = createTruncFolder(builder, newValue, Type::getInt1Ty(context));
  printvalue2((int32_t)flag) printvalue(newValue);
  if (flag == FLAG_RESERVED1 || flag == FLAG_RESERVED5 || flag == FLAG_IF ||
      flag == FLAG_DF)
    return nullptr;

  return FlagList[flag] = newValue;
}
Value* lifterClass::getFlag(Flag flag) {
  if (FlagList[flag])
    return FlagList[flag];

  LLVMContext& context = builder.getContext();
  return ConstantInt::getSigned(Type::getInt1Ty(context), 0);
}

// for love of god this is so ugly
RegisterMap lifterClass::getRegisters() { return Registers; }
void lifterClass::setRegisters(RegisterMap newRegisters) {
  Registers = newRegisters;
}

Value* memoryAlloc;
Value* TEB;
void initMemoryAlloc(Value* allocArg) { memoryAlloc = allocArg; }
Value* getMemory() { return memoryAlloc; }

// todo?
ReverseRegisterMap lifterClass::flipRegisterMap() {
  ReverseRegisterMap RevMap;
  for (const auto& pair : Registers) {
    RevMap[pair.second] = pair.first;
  }
  /*for (const auto& pair : FlagList) {
          RevMap[pair.second] = pair.first;
  }*/
  return RevMap;
}

RegisterMap lifterClass::InitRegisters(Function* function, ZyanU64 rip) {

  // rsp
  // rsp_unaligned = %rsp % 16
  // rsp_aligned_to16 = rsp - rsp_unaligned
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

  Init_Flags();

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

Value* lifterClass::GetValueFromHighByteRegister(int reg) {

  Value* fullRegisterValue = Registers[ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg)];

  Value* shiftedValue =
      createLShrFolder(builder, fullRegisterValue, 8, "highreg");

  Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
  Value* highByteValue = createAndFolder(builder, shiftedValue, FF, "highByte");

  return highByteValue;
}

void lifterClass::SetRFLAGSValue(Value* value) {
  LLVMContext& context = builder.getContext();
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    int shiftAmount = flag;
    Value* shiftedFlagValue = createLShrFolder(
        builder, value, ConstantInt::get(value->getType(), shiftAmount),
        "setflag");
    auto flagValue = createTruncFolder(builder, shiftedFlagValue,
                                       Type::getInt1Ty(context), "flagtrunc");

    setFlag((Flag)flag, flagValue);
  }
  return;
}

Value* lifterClass::GetRFLAGSValue() {
  LLVMContext& context = builder.getContext();
  Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0);
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    Value* flagValue = getFlag((Flag)flag);
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

Value* lifterClass::GetRegisterValue(int key) {

  if (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH ||
      key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH) {
    return GetValueFromHighByteRegister(key);
  }

  int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
                   ? ZydisRegisterGetLargestEnclosing(
                         ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key)
                   : key;

  if (key == ZYDIS_REGISTER_RFLAGS || key == ZYDIS_REGISTER_EFLAGS) {
    return GetRFLAGSValue();
  }

  /*
  if (Registers.find(newKey) == Registers.end()) {
          throw std::runtime_error("register not found"); exit(-1);
  }
  */

  return Registers[newKey];
}

Value* lifterClass::SetValueToHighByteRegister(int reg, Value* value) {
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

Value* lifterClass::SetValueToSubRegister_8b(int reg, Value* value) {
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

Value* lifterClass::SetValueToSubRegister_16b(int reg, Value* value) {

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

void lifterClass::SetRegisterValue(int key, Value* value) {
  if ((key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH ||
       key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH)) {

    value = SetValueToSubRegister_8b(key, value);
  }

  if (((key >= ZYDIS_REGISTER_R8B) && (key <= ZYDIS_REGISTER_R15B)) ||
      ((key >= ZYDIS_REGISTER_AL) && (key <= ZYDIS_REGISTER_BL)) ||
      ((key >= ZYDIS_REGISTER_SPL) && (key <= ZYDIS_REGISTER_DIL))) {

    value = SetValueToSubRegister_8b(key, value);
  }

  if (((key >= ZYDIS_REGISTER_AX) && (key <= ZYDIS_REGISTER_R15W))) {
    value = SetValueToSubRegister_16b(key, value);
  }

  if (key == ZYDIS_REGISTER_RFLAGS) {
    SetRFLAGSValue(value);
    return;
  }

  int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
                   ? ZydisRegisterGetLargestEnclosing(
                         ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key)
                   : key;

  Registers[newKey] = value;
}

Value* lifterClass::GetEffectiveAddress(ZydisDecodedOperand& op,
                                        int possiblesize) {
  LLVMContext& context = builder.getContext();

  Value* effectiveAddress = nullptr;

  Value* baseValue = nullptr;
  if (op.mem.base != ZYDIS_REGISTER_NONE) {
    baseValue = GetRegisterValue(op.mem.base);
    baseValue = createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
    printvalue(baseValue);
  }

  Value* indexValue = nullptr;
  if (op.mem.index != ZYDIS_REGISTER_NONE) {
    indexValue = GetRegisterValue(op.mem.index);

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

Value* lifterClass::GetOperandValue(ZydisDecodedOperand& op, int possiblesize,
                                    string address) {
  LLVMContext& context = builder.getContext();
  auto type = Type::getIntNTy(context, possiblesize);

  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    Value* value = GetRegisterValue(op.reg.value);
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
      baseValue = GetRegisterValue(op.mem.base);
      baseValue =
          createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(op.mem.index);
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

    GEPStoreTracker::loadMemoryOp(retval);

    Value* solvedLoad = GEPStoreTracker::solveLoad(retval);
    if (solvedLoad) {
      return solvedLoad;
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

Value* lifterClass::SetOperandValue(ZydisDecodedOperand& op, Value* value,
                                    string address) {
  LLVMContext& context = builder.getContext();
  value = simplifyValue(
      value,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());

  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    SetRegisterValue(op.reg.value, value);
    return value;
    break;
  }
  case ZYDIS_OPERAND_TYPE_MEMORY: {

    Value* effectiveAddress = nullptr;

    Value* baseValue = nullptr;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
      baseValue = GetRegisterValue(op.mem.base);
      baseValue =
          createZExtFolder(builder, baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(op.mem.index);
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

vector<Value*> lifterClass::GetRFLAGS() {
  vector<Value*> rflags;
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    rflags.push_back(getFlag((Flag)flag));
  }
  return rflags;
}

void lifterClass::pushFlags(vector<Value*> value, string address) {
  LLVMContext& context = builder.getContext();

  auto rsp = GetRegisterValue(ZYDIS_REGISTER_RSP);

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
Value* lifterClass::popStack() {
  LLVMContext& context = builder.getContext();
  auto rsp = GetRegisterValue(ZYDIS_REGISTER_RSP);
  // should we get a address calculator function, do we need that?

  std::vector<Value*> indices;
  indices.push_back(rsp);

  Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,
                                     indices, "GEPLoadPOPStack--");

  auto loadType = Type::getInt64Ty(context);
  auto returnValue = builder.CreateLoad(loadType, pointer, "PopStack-");

  auto CI = ConstantInt::get(rsp->getType(), 8);
  SetRegisterValue(ZYDIS_REGISTER_RSP, createAddFolder(builder, rsp, CI));

  Value* solvedLoad = GEPStoreTracker::solveLoad(returnValue);
  if (solvedLoad) {
    return solvedLoad;
  }

  return returnValue;
}