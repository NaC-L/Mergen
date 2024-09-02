#include "OperandUtils.h"
#include "includes.h"
#include "lifterClass.h"
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
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
        if ((isa<Instruction>(Op) || isa<Argument>(Op)) &&
            Op->hasNUsesOrMore(1))
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
SimplifyQuery lifterClass::createSimplifyQuery(Instruction* Inst) {
  // updateDomTree(*fnc);
  // auto DT = getDomTree();
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

Value* lifterClass::doPatternMatching(Instruction::BinaryOps const I,
                                      Value* const op0, Value* const op1) {

  switch (I) {
  case Instruction::Add: {
    auto and_by_power = [&](Value* op, ConstantInt*& power) {
      Value* LHS;
      return match(op, m_And(m_Value(LHS), m_ConstantInt(power))) &&
             power->getValue().isPowerOf2();
    };

    auto shifted_by_power = [&](Value* op, ConstantInt*& ShiftAmount,
                                Value*& LHS) {
      return match(op, m_LShr(m_Value(LHS), m_ConstantInt(ShiftAmount)));
    };

    auto negative_constant_singlebit = [](Value* op, ConstantInt*& ci) {
      return match(op, m_ConstantInt(ci)) && ci->getValue().isNegative() &&
             ci->getValue().abs().isPowerOf2();
    };

    auto matchPattern = [&](Value* op0, Value* op1) -> Value* {
      ConstantInt *power = nullptr, *ShiftAmount = nullptr, *ci = nullptr;
      Value* LHS = nullptr;

      if (negative_constant_singlebit(op0, ci)) {
        if (shifted_by_power(op1, ShiftAmount, LHS)) {
          if (and_by_power(LHS, power)) {
            auto diff = power->getValue().logBase2() - ShiftAmount->getValue();
            printvalue2(power->getValue());
            printvalue2(ShiftAmount->getValue());
            printvalue2(ci->getValue());
            auto math_is_hard =
                diff.getBoolValue() ? APInt(64, 2) << diff : APInt(64, 1);
            printvalue2(math_is_hard);
            printvalue2(ci->getValue() == -(math_is_hard));
            if (ci->getValue() == -(math_is_hard)) {
              auto zero =
                  builder.getIntN(op1->getType()->getIntegerBitWidth(), 0);
              auto cond = createICMPFolder(llvm::CmpInst::ICMP_EQ, op1, zero);
              return createSelectFolder(cond, ci, zero);
            }
          }
        }
      }
      return nullptr;
    };

    /*
    %not-PConst2-9425 = and i64 %realnot-5369619277-, 64 ( 2 ** 6 = 64)
        %shr-lshr-5368775124- = lshr i64 %not-PConst2-9425, 6
        %realadd-5369433110- = add i64 -1, %shr-lshr-5368775124- ( - (2 ** 6-6)
        ;  ( (a & (2**power) ) >> (power-lula) ) - (2**(lula))
        ;  result = select trunc( (a & (2**power) ) >> (power-lula) ),  0 or
        -(2**(lula))
    */

    // Check if the pattern matches with op0 and op1 in both configurations
    if (auto aaaaa = matchPattern(op0, op1)) {
      return aaaaa;
    }

    break;
  }
  case Instruction::Or: {
    Value *A = nullptr, *B = nullptr, *C = nullptr;

    // Match (~A & B) | (A & C)
    auto handleAndNotPattern = [&](Value* op0, Value* op1) -> bool {
      return (match(op0, m_And(m_Not(m_Value(A)), m_Value(B))) &&
              match(op1, m_And(m_Value(A), m_Value(C))));
    };

    if (handleAndNotPattern(op0, op1) || handleAndNotPattern(op1, op0)) {
      // This matches (~A & B) | (A & C)
      // Simplify to A ? C : B

      // if a is 0, select B
      // if a is -1, select C
      // then... ?
      printvalue(A);
      printvalue(B);
      printvalue(C);
      if (auto X_inst = dyn_cast<Instruction>(A)) {

        auto possible_condition = analyzeValueKnownBits(X_inst, X_inst);
        if (possible_condition.getMaxValue().isAllOnes() &&
            possible_condition.getMinValue().isZero()) {

          return createSelectFolder(A, C, B, "selectEZ");
        }
      }
    }
    break;
  }
  case Instruction::And: {
    // X & ~X
    Value* X = nullptr;
    static auto isXAndNotX = [](Value* op0, Value* op1, Value* X) {
      return (match(op0, m_ZExtOrSelf(m_Not(m_Value(X)))) &&
              match(op1, m_ZExtOrSelf(m_Specific(X)))) ||
             (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
              match(op1, m_Trunc(m_Specific(X))));
    };

    if (isXAndNotX(op0, op1, X) || isXAndNotX(op1, op0, X)) {
      auto possibleSimplifyand = ConstantInt::get(op1->getType(), 0);
      printvalue(possibleSimplifyand);
      return possibleSimplifyand;
    }
    // ~X & ~X

    if (match(op0, m_Not(m_Value(X))) && X == op1)
      return op0;

    break;
  }
  case Instruction::Xor: {
    // X ^ ~X
    Value* X = nullptr;
    static auto isXorNotX = [](Value* op0, Value* op1, Value* X) {
      return (match(op0, m_ZExtOrSelf(m_Not(m_Value(X)))) &&
              match(op1, m_ZExtOrSelf(m_Specific(X)))) ||
             (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
              match(op1, m_Trunc(m_Specific(X))));
    };

    if (isXorNotX(op0, op1, X) || isXorNotX(op1, op0, X)) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), -1);
      printvalue(possibleSimplify);
      return possibleSimplify;
    }

    if (match(op0, m_Specific(op1))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), 0);
      printvalue(possibleSimplify);
      return possibleSimplify;
    }

    Value* A = nullptr;
    Value* B = nullptr;
    Value* C = nullptr;
    Value* D = nullptr;
    // not
    auto handleNegXorOr = [&](Value* op0, Value* op1) -> Value* {
      if (match(op1, m_SpecificInt(-1)) &&
          match(op0, m_Or(m_Value(A), m_Value(B)))) {
        Constant* constant_v = nullptr;

        auto createAndNot = [&](Value* C, Constant* constant_v,
                                const char* suffix) -> Value* {
          return createAndFolder(
              C,
              createXorFolder(constant_v,
                              Constant::getAllOnesValue(constant_v->getType())),
              suffix);
        };

        auto handleNotAOrB = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Not(m_Value(C))) && match(B, m_Constant(constant_v))) {
            // ~(~a | b) -> a & ~b
            printvalue(C);
            return createAndNot(C, constant_v, "not-PConst-");
          }
          return nullptr;
        };

        auto handleAOrBci = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Value(C)) && match(B, m_Constant(constant_v))) {
            // ~(a | b(ci)) -> ~a & ~b
            printvalue(C);
            return createAndFolder(

                createXorFolder(C, Constant::getAllOnesValue(C->getType()),
                                "not_v"),
                createXorFolder(constant_v, Constant::getAllOnesValue(
                                                constant_v->getType())),
                "not-PConst2-");
          }
          return nullptr;
        };

        auto handleNotAOrNotB = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Not(m_Value(C))) && match(B, m_Not(m_Value(D)))) {
            // ~(~a | ~b) -> a & b
            printvalue(C);
            printvalue(D);
            return createAndFolder(C, D, "not-P1-");
          }
          return nullptr;
        };

        auto matchAndSimplify = [&](Value* A, Value* B) -> Value* {
          if (Value* result = handleNotAOrB(A, B))
            return result;
          if (Value* result = handleAOrBci(A, B))
            return result;
          if (Value* result = handleAOrBci(B, A))
            return result;
          if (Value* result = handleNotAOrNotB(A, B))
            return result;
          if (Value* result = handleNotAOrB(A, B))
            return result;
          if (Value* result = handleNotAOrB(B, A))
            return result;
          return nullptr;
        };

        if (Value* result = matchAndSimplify(A, B)) {
          return result;
        } else if (Value* result_swap = matchAndSimplify(B, A)) {
          return result_swap;
        }
      }

      return nullptr;
    };

    if (auto result = handleNegXorOr(op0, op1))
      return result;

    break;
  }

  default: {
    return nullptr;
  }
  }

  return nullptr;
}

KnownBits lifterClass::analyzeValueKnownBits(Value* value, Instruction* ctxI) {
  if (auto v_inst = dyn_cast<Instruction>(value)) {
    // Use find() to check if v_inst exists in the map
    auto it = assumptions->find(v_inst);
    if (it != assumptions->end()) {
      auto a = it->second; // Retrieve the value associated with the instruction
      return KnownBits::makeConstant(a);
    }
  }
  KnownBits knownBits(64);
  knownBits.resetAll();
  if (value->getType() == Type::getInt128Ty(value->getContext()))
    return knownBits;

  if (auto CIv = dyn_cast<ConstantInt>(value)) {
    return KnownBits::makeConstant(APInt(64, CIv->getZExtValue(), false));
  }
  auto SQ = createSimplifyQuery(ctxI);

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

Value* lifterClass::getOrCreate(const InstructionKey& key, const Twine& Name) {
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
            select_inst->getCondition(),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                                select_inst->getTrueValue(), key.operand2),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                                select_inst->getFalseValue(), key.operand2),
            "lola-");
    }

    if (auto select_inst = dyn_cast<SelectInst>(key.operand2)) {
      printvalue2(
          analyzeValueKnownBits(select_inst->getCondition(), select_inst));
      if (isa<ConstantInt>(key.operand1))
        return createSelectFolder(
            select_inst->getCondition(),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                                key.operand1, select_inst->getTrueValue()),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(key.opcode),
                                key.operand1, select_inst->getFalseValue()),
            "lolb-");
    }
    Value *cnd1, *lhs1, *rhs1;
    if (match(key.operand1, m_TruncOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                                   m_Value(rhs1))))) {
      if (auto select_inst = dyn_cast<SelectInst>(key.operand2))
        if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
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
              select_inst->getCondition(),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getTrueValue(), lhs1),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getFalseValue(), rhs1),
              "lol2-");
    }

    Value *cnd, *lhs, *rhs;
    if (match(key.operand2, m_TruncOrSelf(m_Select(m_Value(cnd), m_Value(lhs),
                                                   m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getTrueValue(), lhs),
              builder.CreateBinOp(
                  static_cast<Instruction::BinaryOps>(key.opcode),
                  select_inst->getFalseValue(), rhs),
              "lol2-");
    } else if (match(key.operand2,
                     m_ZExtOrSExtOrSelf(
                         m_Select(m_Value(cnd), m_Value(lhs), m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
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
            select_inst->getCondition(),
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

Value* lifterClass::createInstruction(unsigned opcode, Value* operand1,
                                      Value* operand2, Type* destType,
                                      const Twine& Name) {

  InstructionKey* key;
  if (destType)
    key = new InstructionKey(opcode, operand1, destType);
  else
    key = new InstructionKey(opcode, operand1, operand2);

  Value* newValue = getOrCreate(*key, Name);

  return simplifyValue(
      newValue,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout()); //
}

Value* lifterClass::createSelectFolder(Value* C, Value* True, Value* False,
                                       const Twine& Name) {
  if (auto* CConst = dyn_cast<Constant>(C)) {

    if (CConst->isOneValue()) {
      return True;
    } else if (CConst->isZeroValue()) {
      return False;
    }
  }

  if (True == False)
    return True;

  auto inst = builder.CreateSelect(C, True, False, Name);

  auto RHSKBSELECT_C = analyzeValueKnownBits(C, dyn_cast<Instruction>(inst));
  printvalue2(RHSKBSELECT_C);
  if (!(RHSKBSELECT_C.isUnknown())) {
    auto constant_cond = RHSKBSELECT_C.getConstant();
    if (constant_cond.isOne())
      return True;
    if (constant_cond.isZero())
      return False;
  }

  return inst;
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

Value* lifterClass::folderBinOps(Value* LHS, Value* RHS, const Twine& Name,
                                 Instruction::BinaryOps opcode) {
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
  default: {
    break;
  }
  }
  // this part analyses if we can simplify the instruction
  if (auto simplifiedByPM = doPatternMatching(opcode, LHS, RHS))
    return simplifiedByPM;

  auto inst = createInstruction(opcode, LHS, RHS, nullptr, Name);

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

Value* lifterClass::createAddFolder(Value* LHS, Value* RHS, const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Add);
}

Value* lifterClass::createSubFolder(Value* LHS, Value* RHS, const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Sub);
}

Value* lifterClass::createOrFolder(Value* LHS, Value* RHS, const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Or);
}

Value* lifterClass::createXorFolder(Value* LHS, Value* RHS, const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Xor);
}

Value* lifterClass::createAndFolder(Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::And);
}

Value* lifterClass::createShlFolder(Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::Shl);
}

Value* lifterClass::createLShrFolder(Value* LHS, Value* RHS,
                                     const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::LShr);
}

Value* lifterClass::createShlFolder(Value* LHS, uint64_t RHS,
                                    const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

Value* lifterClass::createShlFolder(Value* LHS, APInt RHS, const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

Value* lifterClass::createLShrFolder(Value* LHS, uint64_t RHS,
                                     const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
Value* lifterClass::createLShrFolder(Value* LHS, APInt RHS, const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
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
    if (P == CmpInst::ICMP_EQ && RHS == SI->getTrueValue())
      return SI->getCondition();
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

Value* lifterClass::createICMPFolder(CmpInst::Predicate P, Value* LHS,
                                     Value* RHS, const Twine& Name) {

  if (auto patternCheck = ICMPPatternMatcher(builder, P, LHS, RHS, Name)) {
    printvalue(patternCheck);
    return patternCheck;
  }

  auto result = builder.CreateICmp(P, LHS, RHS, Name);

  if (auto ctxI = dyn_cast<Instruction>(result)) {

    KnownBits KnownLHS = analyzeValueKnownBits(LHS, ctxI);
    KnownBits KnownRHS = analyzeValueKnownBits(RHS, ctxI);

    if (std::optional<bool> v = foldKnownBits(P, KnownLHS, KnownRHS)) {
      return ConstantInt::get(Type::getInt1Ty(builder.getContext()), v.value());
    }
    printvalue2(KnownLHS) printvalue2(KnownRHS);
  }

  return result;
}

// - probably not needed anymore
Value* lifterClass::createTruncFolder(Value* V, Type* DestTy,
                                      const Twine& Name) {
  Value* result =
      createInstruction(Instruction::Trunc, V, nullptr, DestTy, Name);

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

  return simplifyValue(
      result,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());
}

Value* lifterClass::createZExtFolder(Value* V, Type* DestTy,
                                     const Twine& Name) {
  auto result = createInstruction(Instruction::ZExt, V, nullptr, DestTy, Name);
#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return simplifyValue(
      result,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());
}

Value* lifterClass::createZExtOrTruncFolder(Value* V, Type* DestTy,
                                            const Twine& Name) {
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createZExtFolder(V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(V, DestTy, Name);
  return V;
}

Value* lifterClass::createSExtFolder(Value* V, Type* DestTy,
                                     const Twine& Name) {
  auto result = createInstruction(Instruction::SExt, V, nullptr, DestTy, Name);
#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return simplifyValue(
      result,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout());
}

Value* lifterClass::createSExtOrTruncFolder(Value* V, Type* DestTy,
                                            const Twine& Name) {
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createSExtFolder(V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(V, DestTy, Name);
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
  auto two = ConstantInt::getSigned(Type::getInt1Ty(context), 2);

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

  Registers.vec->push_back(two);
}

// ???
Value* lifterClass::setFlag(Flag flag, Value* newValue) {
  LLVMContext& context = builder.getContext();
  newValue = createTruncFolder(newValue, Type::getInt1Ty(context));
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
RegisterManager& lifterClass::getRegisters() { return Registers; }
void lifterClass::setRegisters(RegisterManager newRegisters) {
  Registers = newRegisters;
}

Value* memoryAlloc;
Value* TEB;
void initMemoryAlloc(Value* allocArg) { memoryAlloc = allocArg; }
Value* getMemory() { return memoryAlloc; }

void lifterClass::InitRegisters(Function* function, ZyanU64 rip) {

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
      Registers.vec->push_back(arg);
      zydisRegister++;
    }
  }
  Init_Flags();

  LLVMContext& context = builder.getContext();

  auto zero = ConstantInt::getSigned(Type::getInt64Ty(context), 0);

  auto value =
      cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), rip));

  auto new_rip = createAddFolder(zero, value);

  Registers.vec->push_back(new_rip);

  auto stackvalue = cast<Value>(
      ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));
  auto new_stack_pointer = createAddFolder(stackvalue, zero);

  Registers[ZYDIS_REGISTER_RSP] = new_stack_pointer;

  return;
}

Value* lifterClass::GetValueFromHighByteRegister(int reg) {

  Value* fullRegisterValue = Registers[ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg)];

  Value* shiftedValue = createLShrFolder(fullRegisterValue, 8, "highreg");

  Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
  Value* highByteValue = createAndFolder(shiftedValue, FF, "highByte");

  return highByteValue;
}

void lifterClass::SetRFLAGSValue(Value* value) {
  LLVMContext& context = builder.getContext();
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    int shiftAmount = flag;
    Value* shiftedFlagValue = createLShrFolder(
        value, ConstantInt::get(value->getType(), shiftAmount), "setflag");
    auto flagValue = createTruncFolder(shiftedFlagValue,
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

        createZExtFolder(flagValue, Type::getInt64Ty(context), "createrflag1"),
        ConstantInt::get(Type::getInt64Ty(context), shiftAmount),
        "createrflag2");
    rflags = createOrFolder(rflags, shiftedFlagValue, "creatingrflag");
  }
  return rflags;
}

Value* lifterClass::GetRegisterValue(int key) {

  if (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH ||
      key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH) {
    return GetValueFromHighByteRegister(key);
  }

  ZydisRegister newKey =
      (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
          ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
                                             (ZydisRegister)key)
          : (ZydisRegister)key;

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

  ZydisRegister fullRegKey = ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
  Value* fullRegisterValue = Registers[fullRegKey];

  Value* eightBitValue = createAndFolder(
      value, ConstantInt::get(value->getType(), 0xFF), "eight-bit");
  Value* shiftedValue = createShlFolder(
      eightBitValue, ConstantInt::get(value->getType(), shiftValue), "shl");

  Value* mask =
      ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
  Value* clearedRegister =
      createAndFolder(fullRegisterValue, mask, "clear-reg");

  shiftedValue = createZExtFolder(shiftedValue, fullRegisterValue->getType());

  Value* newRegisterValue =
      createOrFolder(clearedRegister, shiftedValue, "high_byte");

  return newRegisterValue;
}

Value* lifterClass::SetValueToSubRegister_8b(int reg, Value* value) {
  LLVMContext& context = builder.getContext();
  ZydisRegister fullRegKey = ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, static_cast<ZydisRegister>(reg));
  Value* fullRegisterValue = Registers[fullRegKey];
  fullRegisterValue =
      createZExtOrTruncFolder(fullRegisterValue, Type::getInt64Ty(context));

  uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
  if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH ||
      reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
    mask = 0xFFFFFFFFFFFF00FFULL;
  } else {
    mask = 0xFFFFFFFFFFFFFF00ULL;
  }

  Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
  Value* extendedValue =
      createZExtFolder(value, Type::getInt64Ty(context), "extendedValue");

  Value* maskedFullReg =
      createAndFolder(fullRegisterValue, maskValue, "maskedreg");

  if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH ||
      reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH) {
    extendedValue = createShlFolder(extendedValue, 8, "shiftedValue");
  }

  Value* updatedReg = createOrFolder(maskedFullReg, extendedValue, "newreg");

  printvalue(fullRegisterValue) printvalue(maskValue) printvalue(maskedFullReg)
      printvalue(extendedValue) printvalue(updatedReg);

  Registers[fullRegKey] = updatedReg;

  return updatedReg;
}

Value* lifterClass::SetValueToSubRegister_16b(int reg, Value* value) {

  ZydisRegister fullRegKey = ZydisRegisterGetLargestEnclosing(
      ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
  Value* fullRegisterValue = Registers[fullRegKey];

  Value* last4cleared =
      ConstantInt::get(fullRegisterValue->getType(), 0xFFFFFFFFFFFF0000);
  Value* maskedFullReg =
      createAndFolder(fullRegisterValue, last4cleared, "maskedreg");
  value = createZExtFolder(value, fullRegisterValue->getType());

  Value* updatedReg = createOrFolder(maskedFullReg, value, "newreg");
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

  ZydisRegister newKey =
      (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP)
          ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
                                             (ZydisRegister)key)
          : (ZydisRegister)key;
  Registers[newKey] = value;
}

Value* lifterClass::GetEffectiveAddress(ZydisDecodedOperand& op,
                                        int possiblesize) {
  LLVMContext& context = builder.getContext();

  Value* effectiveAddress = nullptr;

  Value* baseValue = nullptr;
  if (op.mem.base != ZYDIS_REGISTER_NONE) {
    baseValue = GetRegisterValue(op.mem.base);
    baseValue = createZExtFolder(baseValue, Type::getInt64Ty(context));
    printvalue(baseValue);
  }

  Value* indexValue = nullptr;
  if (op.mem.index != ZYDIS_REGISTER_NONE) {
    indexValue = GetRegisterValue(op.mem.index);

    indexValue = createZExtFolder(indexValue, Type::getInt64Ty(context));
    printvalue(indexValue);
    if (op.mem.scale > 1) {
      Value* scaleValue =
          ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
      indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
    }
  }

  if (baseValue && indexValue) {
    effectiveAddress =
        createAddFolder(baseValue, indexValue, "bvalue_indexvalue_set");
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
    effectiveAddress = createAddFolder(effectiveAddress, dispValue, "disp_set");
  }
  printvalue(effectiveAddress);
  return createZExtOrTruncFolder(effectiveAddress,
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
        value = createZExtOrTruncFolder(value, type, "trunc");
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
      baseValue = createZExtFolder(baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(op.mem.index);
      indexValue = createZExtFolder(indexValue, Type::getInt64Ty(context));
      printvalue(indexValue);
      if (op.mem.scale > 1) {
        Value* scaleValue =
            ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
        indexValue = builder.CreateMul(indexValue, scaleValue);
      }
    }

    if (baseValue && indexValue) {
      effectiveAddress =
          createAddFolder(baseValue, indexValue, "bvalue_indexvalue");
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
          createAddFolder(effectiveAddress, dispValue, "memory_addr");
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

    loadMemoryOp(retval);

    Value* solvedLoad = solveLoad(retval);
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
      baseValue = createZExtFolder(baseValue, Type::getInt64Ty(context));
      printvalue(baseValue);
    }

    Value* indexValue = nullptr;
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
      indexValue = GetRegisterValue(op.mem.index);
      indexValue = createZExtFolder(indexValue, Type::getInt64Ty(context));
      printvalue(indexValue);
      if (op.mem.scale > 1) {
        Value* scaleValue =
            ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
        indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
      }
    }

    if (baseValue && indexValue) {
      effectiveAddress =
          createAddFolder(baseValue, indexValue, "bvalue_indexvalue_set");
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
          createAddFolder(effectiveAddress, dispValue, "disp_set");
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

    insertMemoryOp(cast<StoreInst>(store));

    return store;
  } break;

  default: {
    throw std::runtime_error("operand type not implemented");
    // return nullptr;
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
      Value* extendedFlag =
          createZExtFolder(flag, Type::getInt8Ty(context), "pushflag1");
      Value* shiftedFlag = createShlFolder(extendedFlag, j, "pushflag2");
      byteVal = createOrFolder(byteVal, shiftedFlag, "pushflagbyteval");
    }

    std::vector<Value*> indices;
    indices.push_back(rsp);
    Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,
                                       indices, "GEPSTORE-" + address + "-");

    auto store = builder.CreateStore(byteVal, pointer, "storebyte");

    printvalue(rsp) printvalue(pointer) printvalue(byteVal) printvalue(store);

    insertMemoryOp(cast<StoreInst>(store));
    rsp = createAddFolder(rsp, ConstantInt::get(rsp->getType(), 1));
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
  SetRegisterValue(ZYDIS_REGISTER_RSP, createAddFolder(rsp, CI));

  Value* solvedLoad = solveLoad(returnValue);
  if (solvedLoad) {
    return solvedLoad;
  }

  return returnValue;
}