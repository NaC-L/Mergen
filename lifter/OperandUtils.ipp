
#pragma once

#include "CommonDisassembler.hpp"
#include "CommonRegisters.h"
#include "GEPTracker.ipp"
#include "OperandUtils.h"
#include "ZydisDisassembler.hpp"
#include "lifterClass.hpp"
#include "utils.h"
#include <Zydis/Mnemonic.h>
#include <Zydis/Register.h>
#include <Zydis/SharedTypes.h>
#include <cstdio>
#include <iostream>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/KnownBits.h>
#include <llvm/TargetParser/Triple.h>
#include <magic_enum/magic_enum.hpp>
#include <optional>

using namespace llvm;

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

  llvm::ICmpInst::Predicate Pred;
  Value* A;

  if (match(Cond, m_ICmp(Pred, m_Value(A), m_Constant()))) {
    AddAffected(A);

    if (llvm::ICmpInst::isEquality(Pred)) {
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

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
llvm::SimplifyQuery
lifterClass<Mnemonic, Register, T3>::createSimplifyQuery(Instruction* Inst) {
  // updateDomTree(*fnc);
  // auto DT = getDomTree();
  auto DL = fnc->getParent()->getDataLayout();
  static llvm::TargetLibraryInfoImpl TLIImpl(
      llvm::Triple(fnc->getParent()->getTargetTriple()));
  static llvm::TargetLibraryInfo TLI(TLIImpl);

  llvm::SimplifyQuery SQ(DL, &TLI, DT, nullptr, Inst, true, true, nullptr);

  return SQ;
}

using namespace llvm::PatternMatch;

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::doPatternMatching(
    Instruction::BinaryOps const I, Value* const op0, Value* const op1) {

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
    %not-PConsRegister-9425 = and i64 %realnot-5369619277-, 64 ( 2 ** 6 = 64)
        %shr-lshr-5368775124- = lshr i64 %not-PConsRegister-9425, 6
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
      if (auto X_inst = dyn_cast<Instruction>(A)) {

        auto possible_condition = analyzeValueKnownBits(X_inst, X_inst);
        if (possible_condition.getMaxValue().isAllOnes() &&
            possible_condition.getMinValue().isZero()) {
          auto zero = ConstantInt::get(A->getType(), 0);
          auto cond = createICMPFolder(llvm::CmpInst::ICMP_EQ, A, zero);
          return createSelectFolder(cond, B, C, "selectEZ");
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
      return possibleSimplify;
    }

    if (match(op0, m_Specific(op1))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), 0);
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
            return createAndNot(C, constant_v, "not-PConst-");
          }
          return nullptr;
        };

        auto handleAOrBci = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Value(C)) && match(B, m_Constant(constant_v))) {
            // ~(a | b(ci)) -> ~a & ~b
            return createAndFolder(

                createXorFolder(C, Constant::getAllOnesValue(C->getType()),
                                "not_v"),
                createXorFolder(constant_v, Constant::getAllOnesValue(
                                                constant_v->getType())),
                "not-PConsRegister-");
          }
          return nullptr;
        };

        auto handleNotAOrNotB = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Not(m_Value(C))) && match(B, m_Not(m_Value(D)))) {
            // ~(~a | ~b) -> a & b
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

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
KnownBits
lifterClass<Mnemonic, Register, T3>::analyzeValueKnownBits(Value* value,
                                                           Instruction* ctxI) {
  KnownBits knownBits(64);
  knownBits.resetAll();
  if (value->getType()->getIntegerBitWidth() > 64 || isa<UndefValue>(value))
    return knownBits;

  if (auto v_inst = dyn_cast<Instruction>(value)) {
    // Use find() to check if v_inst exists in the map
    auto it = assumptions.find(v_inst);
    if (it != assumptions.end()) {
      auto a = it->second; // Retrieve the value associated with the instruction
      return KnownBits::makeConstant(a);
    }
  }

  if (value->getType() == Type::getInt128Ty(value->getContext()))
    return knownBits;

  if (auto CIv = dyn_cast<ConstantInt>(value)) {
    return KnownBits::makeConstant(APInt(value->getType()->getIntegerBitWidth(),
                                         CIv->getZExtValue(), false));
  }
  auto SQ = createSimplifyQuery(ctxI);

  computeKnownBits(value, knownBits, 0, SQ);
  return knownBits.trunc(value->getType()->getIntegerBitWidth());
}

Value* simplifyValue(Value* v, const DataLayout& DL) {
  if (1 == 1)
    return v;
  if (!isa<Instruction>(v))
    return v;

  Instruction* inst = cast<Instruction>(v);

  /*
  shl al, cl
  where cl is bigger than 8, it just clears the al
  */

  llvm::SimplifyQuery SQ(DL, inst);
  if (auto vconstant = ConstantFoldInstruction(inst, DL)) {
    if (isa<llvm::PoisonValue>(
            vconstant)) // if poison it should be 0 for shifts,
                        // can other operations generate poison
                        // without a poison value anyways?
      return ConstantInt::get(v->getType(), 0);
    return vconstant;
  }

  if (auto vsimplified = simplifyInstruction(inst, SQ)) {

    if (isa<llvm::PoisonValue>(
            vsimplified)) // if poison it should be 0 for shifts,
                          // can other operations generate poison
                          // without a poison value anyways?

      return ConstantInt::get(v->getType(), 0);

    return vsimplified;
  }

  return v;
}

inline bool isCast(uint8_t opcode) {
  return Instruction::Trunc <= opcode && opcode <= Instruction::AddrSpaceCast;
};

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::getOrCreate(
    const InstructionKey& key, uint8_t opcode, const Twine& Name) {
  auto it = cache.lookup(opcode, key);
  if (it) {
    return it;
  }

  Value* newInstruction = nullptr;

  if (isCast(opcode) == 0) {
    // Binary instruction
    if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1)) {
      printvalue2(
          analyzeValueKnownBits(select_inst->getCondition(), select_inst));
      if (isa<ConstantInt>(key.operand2))
        return createSelectFolder(
            select_inst->getCondition(),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                select_inst->getTrueValue(), key.operand2),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                select_inst->getFalseValue(), key.operand2),
            "lola-");
    }

    if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2)) {
      printvalue2(
          analyzeValueKnownBits(select_inst->getCondition(), select_inst));
      if (isa<ConstantInt>(key.operand1))
        return createSelectFolder(
            select_inst->getCondition(),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                key.operand1, select_inst->getTrueValue()),
            builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                key.operand1, select_inst->getFalseValue()),
            "lolb-");
    }
    Value *cnd1, *lhs1, *rhs1;
    if (match(key.operand1, m_TruncOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                                   m_Value(rhs1))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2))
        if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  lhs1, select_inst->getTrueValue()),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  rhs1, select_inst->getFalseValue()),
              "lol2-");
    }

    else if (match(key.operand1,
                   m_ZExtOrSExtOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                               m_Value(rhs1))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2))
        if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  lhs1, select_inst->getTrueValue()),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  rhs1, select_inst->getFalseValue()),
              "lol2-");
    }

    Value *cnd, *lhs, *rhs;
    if (match(key.operand2, m_TruncOrSelf(m_Select(m_Value(cnd), m_Value(lhs),
                                                   m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  select_inst->getTrueValue(), lhs),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  select_inst->getFalseValue(), rhs),
              "lol2-");
    } else if (match(key.operand2,
                     m_ZExtOrSExtOrSelf(
                         m_Select(m_Value(cnd), m_Value(lhs), m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  select_inst->getTrueValue(), lhs),
              builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                                  select_inst->getFalseValue(), rhs),
              "lol2-");
    }
    newInstruction =
        builder.CreateBinOp(static_cast<Instruction::BinaryOps>(opcode),
                            key.operand1, key.operand2, Name);
  } else if (isCast(opcode)) {
    // Cast instruction
    switch (opcode) {

    case Instruction::Trunc:
    case Instruction::ZExt:
    case Instruction::SExt:
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1)) {
        return createSelectFolder(
            select_inst->getCondition(),
            builder.CreateCast(static_cast<Instruction::CastOps>(opcode),
                               select_inst->getTrueValue(), key.destType),
            builder.CreateCast(static_cast<Instruction::CastOps>(opcode),
                               select_inst->getFalseValue(), key.destType),
            "lol-");
      }

      newInstruction =
          builder.CreateCast(static_cast<Instruction::CastOps>(opcode),
                             key.operand1, key.destType);
      break;
    // Add other cast operations as needed
    default:
      UNREACHABLE("Unsupported cast opcode");
    }
  }

  cache.insert(opcode, key, newInstruction);
  return newInstruction;
}

static unsigned getComplexity(const Value* V) {

  if (isa<ConstantInt>(V))
    return isa<UndefValue>(V) ? 0 : 1;

  if (isa<CastInst>(V) || match(V, m_Neg(PatternMatch::m_Value())) ||
      match(V, m_Not(PatternMatch::m_Value())) ||
      match(V, m_FNeg(PatternMatch::m_Value())))
    return 2;

  return 3;
}

static bool isCommutative(const unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Add:
  case Instruction::FAdd:
  case Instruction::Mul:
  case Instruction::FMul:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
    return true;
  default:
    return false;
  }
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createInstruction(
    unsigned opcode, Value* operand1, Value* operand2, Type* destType,
    const Twine& Name) {
  if (isCommutative(opcode)) {
    if (getComplexity(operand1) < getComplexity(operand2)) {
      // if operand1 is less complex, move it to RHS
      std::swap(operand2, operand1);
    }
  }

  InstructionKey key;
  if (destType)
    key = InstructionKey(operand1, destType);
  else
    key = InstructionKey(operand1, operand2);

  Value* newValue = getOrCreate(key, opcode, Name);

  return simplifyValue(
      newValue,
      builder.GetInsertBlock()->getParent()->getParent()->getDataLayout()); //
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createSelectFolder(
    Value* C, Value* True, Value* False, const Twine& Name) {
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

KnownBits computeKnownBitsFromOperation(KnownBits& vv1, KnownBits& vv2,
                                        Instruction::BinaryOps opcode) {
  if (vv1.getBitWidth() > vv2.getBitWidth()) {
    vv2 = vv2.zext(vv1.getBitWidth());
  }
  if (vv2.getBitWidth() > vv1.getBitWidth()) {
    vv1 = vv1.zext(vv2.getBitWidth());
  }
  if (opcode >= Instruction::Shl &&
      opcode <= Instruction::LShr) { // AShr might not make it 0, it also could
                                     // make it -1
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
    std::cout << "\n : " << opcode;
    UNREACHABLE("Unsupported operation in calculatePossibleValues.\n");
    break;
  }
  /*
  case Instruction::ICmp: {
     KnownBits kb(64);
     kb.setAllOnes();
     kb.setAllZero();
     kb.One ^= 1;
     kb.Zero ^= 1;
     switch (cast<llvm::ICmpInst>(inst)->getPredicate()) {
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
       outs() << "\n : " << cast<llvm::ICmpInst>(inst)->getPredicate();
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::folderBinOps(
    Value* LHS, Value* RHS, const Twine& Name, Instruction::BinaryOps opcode) {

  if (LHS->getType() != RHS->getType()) {
    printvalue(LHS);
    printvalue(RHS);
    printvalueforce2(this->counter);
  }

  // ideally we go cheaper to more expensive

  // this part will eliminate unneccesary operations
  switch (opcode) {
    // shifts also should return 0 if shift is bigger than x's bitwidth

  case Instruction::Shl:  // x >> 0 = x , 0 >> x = 0
  case Instruction::LShr: // x << 0 = x , 0 << x = 0
  {

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return LHS;
      if (RHSConst->getZExtValue() >= LHS->getType()->getIntegerBitWidth()) {
        return builder.getIntN(LHS->getType()->getIntegerBitWidth(), 0);
      }
    }
    [[fallthrough]];
  }
  case Instruction::AShr: {

    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return LHS;
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
  Value* inst;
  inst = doPatternMatching(opcode, LHS, RHS);

  if (!inst)
    inst = createInstruction(opcode, LHS, RHS, nullptr, Name);

  // knownbits is recursive, and goes back 5 instructions, ideally it would be
  // not recursive and store the info for all values
  // until then, we just calculate it ourselves

  // we can just swap analyzeValueKnownBits with something else later down the
  // road
  auto LHSKB = analyzeValueKnownBits(LHS, dyn_cast<Instruction>(inst));
  auto RHSKB = analyzeValueKnownBits(RHS, dyn_cast<Instruction>(inst));

  auto computedBits = computeKnownBitsFromOperation(LHSKB, RHSKB, opcode);
  if (computedBits.isConstant() && !computedBits.hasConflict()) {
    return builder.getIntN(LHS->getType()->getIntegerBitWidth(),
                           computedBits.getConstant().getZExtValue());
  }
  /*
  if (auto try_z3 = evaluateLLVMExpression(inst)) {
    if (try_z3.has_value()) {
      printvalueforce(inst);
      printvalueforce(try_z3.value());
      return try_z3.value();
    }
  }
  */
  return inst;
}
/*
#include <z3++.h>

z3::expr llvmToZ3Expr(Value* val, z3::context& c) {
  static llvm::DenseMap<Value*, z3::expr*> cache;
  static int counter = 0;
  if (cache.find(val) != cache.end()) {
    return *cache[val];
  }
  if (ConstantInt* constInt = dyn_cast<ConstantInt>(val)) {
    z3::expr e = c.bv_val(constInt->getValue().getSExtValue(),
                          constInt->getType()->getIntegerBitWidth());
    cache[val] = new z3::expr(e);
    return e;
  } else if (Argument* arg = dyn_cast<Argument>(val)) {
    z3::expr e = c.bv_const(arg->getName().str().c_str(), 64);
    cache[val] = new z3::expr(e);
    return e;
  } else if (CallInst* arg = dyn_cast<CallInst>(val)) {
    z3::expr e = c.bv_const((std::string("callinst") + std::to_string(counter) +
                             (arg->getName().str().c_str()))
                                .c_str(),
                            arg->getType()->getIntegerBitWidth());
    counter++;
    cache[val] = new z3::expr(e);

    return e;
  } else if (Instruction* inst = dyn_cast<Instruction>(val)) {
    switch (inst->getOpcode()) {
    case Instruction::Add: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs + rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::And: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs & rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Or: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs | rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::AShr: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);

      z3::expr result = z3::ashr(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::LShr: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);

      z3::expr result = z3::lshr(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Shl: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = z3::shl(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Mul: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs * rhs;
      cache[val] = new z3::expr(result);
      return result;
    }

    case Instruction::UDiv: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = z3::udiv(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::SDiv: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs / rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::URem: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = z3::urem(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::SRem: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = z3::srem(lhs, rhs);
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Xor: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs ^ rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Sub: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr result = lhs - rhs;
      cache[val] = new z3::expr(result);
      return result;
    }
    case Instruction::Load: {
      z3::expr e = c.bv_const(inst->getName().str().c_str(), 64);
      cache[val] = new z3::expr(e);
      return e;
    }
    case Instruction::Trunc: {
      Value* srcValue = inst->getOperand(0);
      z3::expr srcExpr = llvmToZ3Expr(srcValue, c);
      unsigned targetBitWidth = inst->getType()->getIntegerBitWidth();

      z3::expr truncatedExpr = srcExpr.extract(targetBitWidth - 1, 0);
      cache[val] = new z3::expr(truncatedExpr);
      return truncatedExpr;
    }
    case Instruction::Select: {
      z3::expr condition = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(1), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(2), c);

      z3::expr is_true = condition != 0;
      z3::expr select_expr = z3::ite(is_true, lhs, rhs);
      cache[val] = new z3::expr(select_expr);
      return select_expr;
    }
    case Instruction::ICmp: {
      z3::expr lhs = llvmToZ3Expr(inst->getOperand(0), c);
      z3::expr rhs = llvmToZ3Expr(inst->getOperand(1), c);

      z3::expr bool_result = lhs;
      switch (cast<llvm::ICmpInst>(inst)->getPredicate()) {
      case llvm::CmpInst::ICMP_EQ:
        bool_result = (lhs == rhs);
        break;
      case llvm::CmpInst::ICMP_NE:
        bool_result = (lhs != rhs);
        break;
      case llvm::CmpInst::ICMP_SLE:
        bool_result = z3::sle(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_SLT:
        bool_result = z3::slt(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_ULE:
        bool_result = z3::ule(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_ULT:
        bool_result = z3::ult(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_SGE:
        bool_result = z3::sge(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_SGT:
        bool_result = z3::sgt(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_UGE:
        bool_result = z3::uge(lhs, rhs);
        break;
      case llvm::CmpInst::ICMP_UGT:
        bool_result = z3::ugt(lhs, rhs);
        break;
      default:
        UNREACHABLE("Unsupported comparison predicate !");
        return c.bv_val(-1, 32);
      }

      z3::expr int_result =
          z3::ite(bool_result, c.bv_val(1, 1), c.bv_val(0, 1));
      cache[val] = new z3::expr(int_result);
      return int_result;
    }
    case Instruction::ZExt:
    case Instruction::SExt: {
      Value* srcValue = inst->getOperand(0);
      z3::expr srcExpr = llvmToZ3Expr(srcValue, c);
      unsigned srcBitWidth = srcExpr.get_sort().bv_size();
      unsigned targetBitWidth = inst->getType()->getIntegerBitWidth();
      z3::expr extendedExpr =
          inst->getOpcode() == Instruction::ZExt
              ? z3::zext(srcExpr, targetBitWidth - srcBitWidth)
              : z3::sext(srcExpr, targetBitWidth - srcBitWidth);

      cache[val] = new z3::expr(extendedExpr);
      return extendedExpr;
    }
    default:
      std::cerr << "Unsupported instruction : " << inst->getOpcodeName() << " !"
                << std::endl;
      UNREACHABLE("Unsupported instruction !");
      return c.bv_val(0, 64);
    }
  }

  UNREACHABLE("Unsupported!");
  return c.bv_val(0, 64);
}

std::optional<Value*> lifterClass<Mnemonic, Register,
T3>::evaluateLLVMExpression(Value* value) { static z3::context c;

  printvalue(value);

  z3::expr expr = llvmToZ3Expr(value, c);

  if (auto inst = dyn_cast<Instruction>(value)) {

  } else
    return std::nullopt;
  printvalue2(expr);
  z3::expr simplified_expr = expr.simplify();
  printvalue2(simplified_expr);
  if (simplified_expr.get_sort().bv_size() != 64) {
    return std::nullopt;
  }
  if (simplified_expr.is_numeral()) {
    return ConstantInt::get(value->getType(),
                            simplified_expr.get_numeral_uint64());
  }

  static z3::solver s =
      (z3::tactic(c, "solve-eqs") & z3::tactic(c, "propagate-values") &
       z3::tactic(c, "bit-blast") & z3::tactic(c, "elim-uncnstr") &
       z3::tactic(c, "qe-light") & z3::tactic(c, "elim-uncnstr") &
       z3::tactic(c, "reduce-args") & z3::tactic(c, "qe-light") &
       z3::tactic(c, "smt"))
          .mk_solver();
  Z3_global_param_set("timeout", "1000");
  s.reset();

  const auto lowstack = c.bv_val(STACKP_VALUE - 0x10000, 64);
  const auto higstack = c.bv_val(STACKP_VALUE + 0x10000, 64);
  const auto low_bin = c.bv_val(0x140000000, 64);
  const auto high_bin = c.bv_val(0x140000000 + 0x144f000, 64);

  auto bound_stack =
      ((simplified_expr >= lowstack) && (simplified_expr <= higstack));

  auto bound_bin_0 = (simplified_expr >= low_bin);
  auto bound_bin_1 = (simplified_expr <= high_bin);
  auto bound_bin = bound_bin_0 && bound_bin_1;
  s.add(bound_stack || bound_bin);
  for (const auto& it : assumptions) {
    auto cnd = llvmToZ3Expr(it.first, c);
    auto v = llvmToZ3Expr(ConstantInt::get(it.first->getType(), it.second), c);
    s.add(cnd == v);
  }
  auto status = s.check();
  if (status == z3::sat) {

    z3::model m = s.get_model();

    z3::expr value_expr = m.eval(simplified_expr, true);

    printvalue2(value_expr);

    s.add((simplified_expr != value_expr));

    if (s.check() != z3::sat) {
      return ConstantInt::get(value->getType(),
                              value_expr.get_numeral_uint64());
    }
  }

  return std::nullopt;
}
*/
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createGEPFolder(Type* Type,
                                                            Value* Base,
                                                            Value* Address,
                                                            const Twine& Name) {
  GEPinfo key = {Address, (uint8_t)(Type->getScalarSizeInBits()), 1};
  auto it = GEPcache.lookup(key);
  if (it) {
    return it;
  }

  std::vector<Value*> indices;
  indices.push_back(Address);
  auto v = builder.CreateGEP(Type, Base, indices);
  GEPcache.insert({key, v});
  return v;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createAddFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Add);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createSubFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Sub);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createOrFolder(Value* LHS,
                                                           Value* RHS,
                                                           const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Or);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createXorFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Xor);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createNotFolder(Value* LHS,
                                                            const Twine& Name) {

  return createXorFolder(LHS, Constant::getAllOnesValue(LHS->getType()), Name);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createAndFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::And);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createMulFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::Mul);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createSDivFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::SDiv);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createUDivFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::UDiv);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createSRemFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::SRem);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createURemFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::URem);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createShlFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::Shl);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createLShrFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::LShr);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createAShrFolder(Value* LHS, Value* RHS,
                                                      const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::AShr);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createShlFolder(Value* LHS,
                                                            uint64_t RHS,
                                                            const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createShlFolder(Value* LHS,
                                                            APInt RHS,
                                                            const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createLShrFolder(Value* LHS, uint64_t RHS,
                                                      const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createLShrFolder(Value* LHS, APInt RHS,
                                                      const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
std::optional<bool> foldKnownBits(CmpInst::Predicate P, const KnownBits& LHS,
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
    return std::nullopt;
  }

  return std::nullopt;
}

Value* ICMPPatternMatcher(IRBuilder<llvm::InstSimplifyFolder>& builder,
                          CmpInst::Predicate P, Value* LHS, Value* RHS,
                          const Twine& Name) {
  if (auto SI = dyn_cast<SelectInst>(LHS)) {
    if (P == CmpInst::ICMP_EQ && RHS == SI->getTrueValue())
      return SI->getCondition();
  }
  // c = add a, b
  // cmp x, c, 0
  // =>
  // cmp x, a, -b

  // lhs is a bin op

  return nullptr;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createICMPFolder(
    CmpInst::Predicate P, Value* LHS, Value* RHS, const Twine& Name) {
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createTruncFolder(Value* V, Type* DestTy,
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createZExtFolder(Value* V, Type* DestTy,
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createZExtOrTruncFolder(
    Value* V, Type* DestTy, const Twine& Name) {
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createZExtFolder(V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(V, DestTy, Name);
  return V;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::createSExtFolder(Value* V, Type* DestTy,
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::createSExtOrTruncFolder(
    Value* V, Type* DestTy, const Twine& Name) {
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::Init_Flags() {
  LLVMContext& context = builder.getContext();
  auto zero = ConstantInt::getSigned(Type::getInt1Ty(context), 0);
  auto one = ConstantInt::getSigned(Type::getInt1Ty(context), 1);
  auto two = ConstantInt::getSigned(Type::getInt1Ty(context), 2);

  FlagList[FLAG_CF].set(zero);
  FlagList[FLAG_PF].set(zero);
  FlagList[FLAG_AF].set(zero);
  FlagList[FLAG_ZF].set(zero);
  FlagList[FLAG_SF].set(zero);
  FlagList[FLAG_TF].set(zero);
  FlagList[FLAG_IF].set(one);
  FlagList[FLAG_DF].set(zero);
  FlagList[FLAG_OF].set(zero);

  FlagList[FLAG_RESERVED1].set(one);
  Registers[Register::RFLAGS] = two;
}

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::setFlag(const Flag flag,
                                                    Value* newValue) {
  LLVMContext& context = builder.getContext();
  newValue = createTruncFolder(newValue, Type::getInt1Ty(context));
  // printvalue2((int32_t)flag) printvalue(newValue);
  if (flag == FLAG_RESERVED1 || flag == FLAG_RESERVED5 || flag == FLAG_IF)
    return nullptr;

  FlagList[flag].set(newValue); // Set the new value directly
  return newValue;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::setFlag(
    const Flag flag, std::function<Value*()> calculation) {
  // If the flag is one of the reserved ones, do not modify
  if (flag == FLAG_RESERVED1 || flag == FLAG_RESERVED5 || flag == FLAG_IF)
    return;

  // lazy calculation
  FlagList[flag].setCalculation(calculation);
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
LazyValue lifterClass<Mnemonic, Register, T3>::getLazyFlag(const Flag flag) {
  //
  return FlagList[flag];
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::getFlag(const Flag flag) {
  Value* result = FlagList[flag].get(); // Retrieve the value,
  if (result) // if its somehow nullptr, just return False as value
    return createTruncFolder(result, builder.getInt1Ty());

  LLVMContext& context = builder.getContext();
  return ConstantInt::getSigned(Type::getInt1Ty(context), 0);
}

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::InitRegisters(Function* function,
                                                        const ZyanU64 rip) {

  // rsp
  // rsp_unaligned = %rsp % 16
  // rsp_aligned_to16 = rsp - rsp_unaligned
  auto reg = Register::RAX;

  auto argEnd = function->arg_end();
  for (auto argIt = function->arg_begin(); argIt != argEnd; ++argIt) {

    Argument* arg = &*argIt;
    arg->setName(magic_enum::enum_name(reg));

    if (std::next(argIt) == argEnd) {
      arg->setName("memory");
      memoryAlloc = arg;
    } else {
      // arg->setName(ZydisRegisterGetString(zydisRegister));
      Registers[reg] = arg;
      reg = static_cast<Register>(static_cast<int>(reg) + 1);
    }
  }
  Init_Flags();

  LLVMContext& context = builder.getContext();

  const auto zero = ConstantInt::getSigned(Type::getInt64Ty(context), 0);

  /*
    Registers[Register::RBP] = zero;


    Registers[Register::RAX] = filebase;
    Registers[Register::RBX] = filebase;

    Registers[Register::RSI] = zero;
    Registers[Register::RDI] = zero;
    Registers[Register::R8] = filesize;
    Registers[Register::R9] = filebase;
    Registers[Register::R10] = zero;
    Registers[Register::R11] = zero;
    Registers[Register::R12] = zero;
    Registers[Register::R13] = zero;
    Registers[Register::R14] = zero;
    Registers[Register::R15] = zero;
  */

  auto value =
      cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context), rip));

  auto new_rip = createAddFolder(zero, value);

  Registers[Register::RIP] = new_rip;

  auto stackvalue = cast<Value>(
      ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));
  auto new_stack_pointer = createAddFolder(stackvalue, zero);

  Registers[Register::RSP] = new_stack_pointer;
  /*
  for (auto& reg : RegistersFP.vec) {
    reg.v1 = ConstantInt::get(Type::getInt64Ty(context), 0);
    reg.v2 = ConstantInt::get(Type::getInt64Ty(context), 0);
  }
  */
  return;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetValueFromHighByteRegister(
    const Register reg) {

  Value* fullRegisterValue = Registers[getBiggestEncoding(reg)];

  Value* shiftedValue = createLShrFolder(fullRegisterValue, 8, "highreg");

  Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
  Value* highByteValue = createAndFolder(shiftedValue, FF, "highByte");

  return createTruncFolder(highByteValue, builder.getIntNTy(8));
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::SetRFLAGSValue(Value* value) {
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetRFLAGSValue() {
  LLVMContext& context = builder.getContext();
  Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0);
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    Value* flagValue = getFlag((Flag)flag);
    int shiftAmount = flag;
    Value* shiftedFlagValue = createShlFolder(

        createZExtFolder(flagValue, Type::getInt64Ty(context), "createrflag1-"),
        ConstantInt::get(Type::getInt64Ty(context), shiftAmount),
        "createrflag2-");
    rflags = createOrFolder(rflags, shiftedFlagValue, "creatingrflag");
  }
  return rflags;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value*
lifterClass<Mnemonic, Register, T3>::GetRegisterValue(const Register key) {
  // printvalue2(magic_enum::enum_name(key));

  if (key == Register::RIP || key == Register::EIP) {
    return ConstantInt::getSigned(BinaryOperations::getBitness() == 64
                                      ? Type::getInt64Ty(builder.getContext())
                                      : Type::getInt32Ty(builder.getContext()),
                                  blockInfo.runtime_address);
  }

  if (key == Register::AH || key == Register::CH || key == Register::DH ||
      key == Register::BH) {
    return GetValueFromHighByteRegister(key);
  }

  if (key == Register::RFLAGS || key == Register::EFLAGS) {
    return GetRFLAGSValue();
  }

  if (key == Register::GS) {
    auto funcInfo = new funcsignatures<Register>::functioninfo("loadGS", {});
    return callFunctionIR("loadGS", funcInfo);
  }
  if (key == Register::DS) {
    auto funcInfo = new funcsignatures<Register>::functioninfo("loadDS", {});
    return callFunctionIR("loadDS", funcInfo);
  }
  /*
  if (Registers.find(newKey) == Registers.end()) {
          UNREACHABLE("register not found"); exit(-1);
  }
  */

  Register largestKey = getBiggestEncoding(key);
  // dont truncate here?
  return Registers[largestKey];
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::SetValueToHighByteRegister(
    const Register reg, Value* value) {
  LLVMContext& context = builder.getContext();
  int shiftValue = 8;

  Register fullRegKey = getBiggestEncoding(reg);
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
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::SetValueToSubRegister_8b(
    const Register reg, Value* value) {
  LLVMContext& context = builder.getContext();
  Register fullRegKey = getBiggestEncoding(reg);
  Value* fullRegisterValue = Registers[fullRegKey];
  fullRegisterValue =
      createZExtOrTruncFolder(fullRegisterValue, Type::getInt64Ty(context));

  Value* extendedValue =
      createZExtFolder(value, Type::getInt64Ty(context), "extendedValue");

  bool isHighByteReg = (reg == Register::AH || reg == Register::CH ||
                        reg == Register::DH || reg == Register::BH);

  uint64_t mask = isHighByteReg ? 0xFFFFFFFFFFFF00FFULL : 0xFFFFFFFFFFFFFF00ULL;

  Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
  Value* maskedFullReg =
      createAndFolder(fullRegisterValue, maskValue, "maskedreg");

  if (isHighByteReg) {
    extendedValue = createShlFolder(extendedValue, 8, "shiftedValue");
  }

  Value* updatedReg = createOrFolder(maskedFullReg, extendedValue, "newreg");

  printvalue(fullRegisterValue) printvalue(maskValue) printvalue(maskedFullReg)
      printvalue(extendedValue) printvalue(updatedReg);

  Registers[fullRegKey] = updatedReg;

  return updatedReg;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::SetValueToSubRegister_16b(
    const Register reg, Value* value) {

  Register fullRegKey = getBiggestEncoding(reg);
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

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::SetRegisterValue(const Register key,
                                                           Value* value) {

  if (key == Register::EIP)
    return;

  if ((key >= Register::AL) && (key <= Register::R15B)) {
    value = SetValueToSubRegister_8b(key, value);
  }

  if (((key >= Register::AX) && (key <= Register::R15W))) {
    value = SetValueToSubRegister_16b(key, value);
  }

  if (key == Register::RFLAGS) {
    SetRFLAGSValue(value);
    return;
  }
  printvalue2(magic_enum::enum_name(key));
  printvalue(value);
  Register newKey = getBiggestEncoding(key);
  Registers[newKey] = value;
}

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetEffectiveAddress() {
  LLVMContext& context = builder.getContext();

  Value* effectiveAddress = nullptr;

  Value* baseValue = nullptr;

  if (instruction.mem_base != Register::None) {
    baseValue = GetRegisterValue(instruction.mem_base);
    baseValue = createZExtFolder(baseValue, Type::getInt64Ty(context));
    printvalue(baseValue);
  }
  Value* indexValue = nullptr;

  if (instruction.mem_index != Register::None) {
    indexValue = GetRegisterValue(instruction.mem_index);

    indexValue = createZExtFolder(indexValue, Type::getInt64Ty(context));
    printvalue(indexValue);
    Value* scaleValue =
        ConstantInt::get(Type::getInt64Ty(context), instruction.mem_scale);
    indexValue = createMulFolder(indexValue, scaleValue, "mul_ea");
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

  printvalue2(instruction.mem_disp);
  if (instruction.mem_disp) {

    Value* dispValue =
        ConstantInt::get(Type::getInt64Ty(context), instruction.mem_disp);

    effectiveAddress = createAddFolder(effectiveAddress, dispValue, "disp_set");
  }
  printvalue(effectiveAddress);
  return effectiveAddress;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::getPointer(Value* address) {

  LLVMContext& context = builder.getContext();
  std::vector<Value*> indices;
  indices.push_back(address);

  auto memoryOperand = memoryAlloc;
  //
  // if (segment == Register::GS)
  //     memoryOperand = TEB;

  Value* pointer =
      builder.CreateGEP(Type::getInt8Ty(context), memoryOperand, indices);
  return pointer;
}

// takes address, not pointers
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetMemoryValue(Value* address,
                                                           uint8_t size) {

  // convert to pointer first
  auto pointer = getPointer(address);

  LazyValue retval([this, pointer, size]() {
    return builder.CreateLoad(builder.getIntNTy(size),
                              pointer /*, "Loadxd-" + address + "-"*/);
  });

  loadMemoryOp(pointer);

  if (Value* solvedLoad = solveLoad(retval, pointer, size)) {
    // if can solve, return
    // todo: use optional instead
    return solvedLoad;
  }

  return retval.get();
}

// takes address, not pointers
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::SetMemoryValue(llvm::Value* address,
                                                         llvm::Value* value) {

  auto pointer = getPointer(address);

  auto store = builder.CreateStore(value, pointer);

  insertMemoryOp(cast<StoreInst>(store));
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetIndexValue(uint8_t index) {

  auto type = instruction.types[index];
  printvalue2(index);
  printvalue2(magic_enum::enum_name(type));

  switch (type) {
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    auto reg = instruction.regs[index];

    return createZExtOrTruncFolder(GetRegisterValue(reg),
                                   builder.getIntNTy(GetTypeSize(type)));
  }

  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    int size = 0;

    switch (type) {
    case OperandType::Immediate8:
      size = 8;
      break;
    case OperandType::Immediate16:
      size = 16;
      break;
    case OperandType::Immediate32:
      size = 32;
      break;
    case OperandType::Immediate64:
      size = 64;
      break;
    default:
      UNREACHABLE("??");
    }

    return builder.getIntN(size, instruction.immediate);
  }

  case OperandType::Immediate8_2nd: {
    return builder.getIntN(8, instruction.immediate2);
  }

  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64: {
    int size = 0;

    switch (type) {

    case OperandType::Memory8:
      size = 8;
      break;
    case OperandType::Memory16:
      size = 16;
      break;
    case OperandType::Memory32:
      size = 32;
      break;
    case OperandType::Memory64:
      size = 64;
      break;

    default:
      UNREACHABLE("??");
    }
    auto addr = GetEffectiveAddress();
    return GetMemoryValue(addr, size);
  }
  default: {
    printvalueforce2(magic_enum::enum_name(type));
    printvalueforce2((uint32_t)index);
    UNREACHABLE("idk");
  }
  }
}

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::SetIndexValue(uint8_t index,
                                                        Value* value) {

  auto type = instruction.types[index];

  switch (type) {
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    auto reg = instruction.regs[index];

    // TODO: do we need to remove this sext from here?
    // value =
    //    createSExtOrTruncFolder(value,
    //    builder.getIntNTy(getRegisterSize(reg)));

    SetRegisterValue(reg, value);
    return;
  }

  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    UNREACHABLE("Cant set imm operands");
  }

  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64: {
    int size = 0;

    switch (type) {

    case OperandType::Memory8:
      size = 8;
      break;
    case OperandType::Memory16:
      size = 16;
      break;
    case OperandType::Memory32:
      size = 32;
      break;
    case OperandType::Memory64:
      size = 64;
      break;

    default:
      UNREACHABLE("??");
    }

    // TODO: do we need to remove this sext from here?
    value = createSExtOrTruncFolder(value, builder.getIntNTy(size));
    auto addr = GetEffectiveAddress();
    SetMemoryValue(addr, value);

    return;
  }
  default: {
    UNREACHABLE("idk");
  }
  }
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::GetOperandValue(
    const ZydisDecodedOperand& op, int possiblesize,
    const std::string& address) {}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::SetOperandValue(
    const ZydisDecodedOperand& op, Value* value, const std::string& address) {}

template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
std::vector<Value*> lifterClass<Mnemonic, Register, T3>::GetRFLAGS() {
  std::vector<Value*> rflags;
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    rflags.push_back(getFlag((Flag)flag));
  }
  return rflags;
}
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
void lifterClass<Mnemonic, Register, T3>::pushFlags(
    const std::vector<Value*>& value, const std::string& address) {
  LLVMContext& context = builder.getContext();

  auto rsp = GetRegisterValue(Register::RSP);

  for (size_t i = 0; i < value.size(); i += 8) {
    Value* byteVal = ConstantInt::get(Type::getInt8Ty(context), 0);
    for (size_t j = 0; j < 8 && (i + j) < value.size(); ++j) {
      Value* flag = value[i + j];
      Value* extendedFlag =
          createZExtFolder(flag, Type::getInt8Ty(context), "pushflag1");
      Value* shiftedFlag = createShlFolder(extendedFlag, j, "pushflag2");
      byteVal = createOrFolder(byteVal, shiftedFlag, "pushflagbyteval");
    }

    Value* pointer = createGEPFolder(Type::getInt8Ty(context), memoryAlloc, rsp,
                                     "GEPSTORE-" + address + "-");

    auto store = builder.CreateStore(byteVal, pointer, "storebyte");

    insertMemoryOp(cast<StoreInst>(store));
    rsp = createAddFolder(rsp, ConstantInt::get(rsp->getType(), 1));
  }
}

// return [rsp], rsp+=8
template <typename Mnemonic, typename Register,
          template <typename, typename> class T3>
Value* lifterClass<Mnemonic, Register, T3>::popStack(int size) {
  LLVMContext& context = builder.getContext();
  auto rsp = GetRegisterValue(Register::RSP);
  // should we get a address calculator function, do we need that?

  Value* pointer = createGEPFolder(Type::getInt8Ty(context), memoryAlloc, rsp,
                                   "GEPLoadPOPStack--");

  auto loadType = Type::getInt64Ty(context);
  LazyValue returnValue([this, loadType, pointer]() {
    return builder.CreateLoad(loadType, pointer /*, "PopStack-"*/);
  });

  auto CI = ConstantInt::get(rsp->getType(), size);
  SetRegisterValue(Register::RSP, createAddFolder(rsp, CI));

  Value* solvedLoad =
      solveLoad(returnValue, pointer, loadType->getIntegerBitWidth());
  if (solvedLoad) {
    return solvedLoad;
  }

  return returnValue.get();
}