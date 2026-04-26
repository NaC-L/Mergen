
#include "PathSolver.h"
#include "CustomPasses.hpp"
#include "Utils.h"
#include <llvm/ADT/DenseMap.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

// Recursively simplify a Value bottom-up using LLVM's InstSimplify. Returns
// the simplified value (which may be a Constant or another existing SSA
// value). Does NOT mutate IR. Useful when the path solver receives a
// def-chain that LLVM's later O1 would collapse via algebraic identities
// (Denuvo dispatchers wrap their target in `(x ^ k) + (-(x ^ k) + n)` style
// noise specifically to defeat per-op simplification at lift time).
// Cancellation-aware simplifier built on top of InstSimplify.
//
// LLVM's per-op simplifier handles `x + (-x) = 0`, but Denuvo dispatchers
// wrap the actual jump target in deeper noise like `x + (-(x + n)) = -n`,
// which requires distributing the negation through the inner sum first.
// That distribution is InstCombine territory and is far too expensive to
// run mid-lift on the whole function.
//
// Instead, when an add/sub/neg chain reaches the path solver, we expand
// it into a canonical sum-of-terms `{Value* -> int64 coefficient}` map,
// combining like terms by coefficient. If everything cancels except for a
// single term, that term's value (negated when coefficient is -1) is the
// real result. The terms themselves are first deep-simplified, so loads,
// xors, and other leaves participate in their own canonical form.
//
// This intentionally does NOT mutate the IR. The path solver only needs
// to read the canonical value once.
static bool isNegationOf(Value* V, Value*& innerOut) {
  if (auto* binOp = dyn_cast<BinaryOperator>(V)) {
    if (binOp->getOpcode() == Instruction::Sub) {
      if (auto* lhs = dyn_cast<ConstantInt>(binOp->getOperand(0))) {
        if (lhs->isZero()) {
          innerOut = binOp->getOperand(1);
          return true;
        }
      }
    }
  }
  return false;
}

static llvm::Value* deepSimplifyImpl(
    Value* V, const DataLayout& DL,
    IRBuilder<InstSimplifyFolder>* builder,
    DenseMap<Value*, Value*>& cache, unsigned depth);

// Expand `V` (with overall sign `coeff`) into a sum-of-terms map.
// Recurses through Add/Sub/Neg only — every other node is a leaf.
static void collectTerms(Value* V, int64_t coeff,
                         const DataLayout& DL,
                         IRBuilder<InstSimplifyFolder>* builder,
                         DenseMap<Value*, Value*>& simplifyCache,
                         DenseMap<Value*, int64_t>& termsOut,
                         unsigned depth) {
  if (depth > 24) {
    termsOut[V] += coeff;
    return;
  }
  Value* simplified =
      deepSimplifyImpl(V, DL, builder, simplifyCache, depth);
  if (auto* CI = dyn_cast<ConstantInt>(simplified)) {
    APInt v = CI->getValue();
    if (coeff < 0) v = -v;
    Constant* zero = ConstantInt::get(CI->getType(), 0);
    termsOut[zero] += static_cast<int64_t>(v.getSExtValue());
    return;
  }
  if (auto* binOp = dyn_cast<BinaryOperator>(simplified)) {
    if (binOp->getOpcode() == Instruction::Add) {
      collectTerms(binOp->getOperand(0), coeff, DL, builder, simplifyCache,
                   termsOut, depth + 1);
      collectTerms(binOp->getOperand(1), coeff, DL, builder, simplifyCache,
                   termsOut, depth + 1);
      return;
    }
    if (binOp->getOpcode() == Instruction::Sub) {
      collectTerms(binOp->getOperand(0), coeff, DL, builder, simplifyCache,
                   termsOut, depth + 1);
      collectTerms(binOp->getOperand(1), -coeff, DL, builder, simplifyCache,
                   termsOut, depth + 1);
      return;
    }
  }
  Value* inner = nullptr;
  if (isNegationOf(simplified, inner)) {
    collectTerms(inner, -coeff, DL, builder, simplifyCache, termsOut,
                 depth + 1);
    return;
  }
  termsOut[simplified] += coeff;
}

// Build `coeff * V` at the builder's insert point. coeff is ±1 or 0.
static Value* materializeTerm(
    Value* V, int64_t coeff, Type* ty,
    IRBuilder<InstSimplifyFolder>* builder) {
  if (coeff == 0) return ConstantInt::get(ty, 0);
  if (V->getType() != ty) {
    return nullptr;
  }
  if (coeff == 1) return V;
  if (coeff == -1) {
    return builder->CreateNeg(V);
  }
  return builder->CreateMul(V, ConstantInt::getSigned(ty, coeff));
}

static llvm::Value* deepSimplifyImpl(
    Value* V, const DataLayout& DL,
    IRBuilder<InstSimplifyFolder>* builder,
    DenseMap<Value*, Value*>& cache, unsigned depth) {
  if (depth > 24) return V;
  auto it = cache.find(V);
  if (it != cache.end()) return it->second;
  // Pre-seed the cache to short-circuit cycles (PHI nodes etc).
  cache[V] = V;

  Value* result = V;
  if (auto* I = dyn_cast<Instruction>(V)) {
    SmallVector<Value*, 4> simplifiedOps;
    bool anyChanged = false;
    for (Use& opUse : I->operands()) {
      Value* op = opUse.get();
      Value* simplified =
          deepSimplifyImpl(op, DL, builder, cache, depth + 1);
      simplifiedOps.push_back(simplified);
      if (simplified != op) anyChanged = true;
    }
    SimplifyQuery SQ(DL, I);
    Value* simplified = anyChanged
        ? simplifyInstructionWithOperands(I, simplifiedOps, SQ)
        : simplifyInstruction(I, SQ);
    if (simplified) result = simplified;
  }

  // Sum-of-terms cancellation pass: only meaningful for add/sub/neg-rooted
  // chains over an integer type.
  if (auto* binOp = dyn_cast<BinaryOperator>(result)) {
    bool isAddOrSub = binOp->getOpcode() == Instruction::Add ||
                      binOp->getOpcode() == Instruction::Sub;
    Value* innerNeg = nullptr;
    bool isNeg = isNegationOf(binOp, innerNeg);
    if ((isAddOrSub || isNeg) && binOp->getType()->isIntegerTy()) {
      DenseMap<Value*, int64_t> terms;
      collectTerms(result, 1, DL, builder, cache, terms, depth);
      Value* constantTermKey = nullptr;
      int64_t constantTermSum = 0;
      SmallVector<std::pair<Value*, int64_t>, 8> nonConst;
      for (auto& kv : terms) {
        if (kv.second == 0) continue;
        if (auto* C = dyn_cast<ConstantInt>(kv.first)) {
          if (C->isZero()) {
            constantTermKey = kv.first;
            constantTermSum += kv.second;
            continue;
          }
        }
        nonConst.emplace_back(kv.first, kv.second);
      }
      Type* ty = binOp->getType();
      auto countOriginalAddSubOps = [&]() {
        // Cheap upper-bound proxy for chain depth: the longer the chain,
        // the more it costs us to NOT simplify. We bail out when the
        // canonical form would be larger than the original to avoid
        // bloating the IR with synthesized add/sub trees that O1 would
        // produce a different way.
        unsigned count = 0;
        SmallVector<Value*, 16> stack;
        DenseSet<Value*> seen;
        stack.push_back(binOp);
        while (!stack.empty()) {
          Value* x = stack.pop_back_val();
          if (!seen.insert(x).second) continue;
          if (auto* b = dyn_cast<BinaryOperator>(x)) {
            if (b->getOpcode() == Instruction::Add ||
                b->getOpcode() == Instruction::Sub) {
              ++count;
              stack.push_back(b->getOperand(0));
              stack.push_back(b->getOperand(1));
            }
          }
        }
        return count;
      };

      if (nonConst.empty() && constantTermSum != 0) {
        result = ConstantInt::getSigned(ty, constantTermSum);
      } else if (nonConst.empty()) {
        result = ConstantInt::get(ty, 0);
      } else if (nonConst.size() == 1 && constantTermSum == 0) {
        Value* term = nonConst[0].first;
        int64_t c = nonConst[0].second;
        if (c == 1) {
          result = term;
        } else if (c == -1) {
          // Reuse the negation if it already exists in IR; otherwise emit.
          bool found = false;
          for (User* U : term->users()) {
            if (auto* candidate = dyn_cast<BinaryOperator>(U)) {
              Value* inner = nullptr;
              if (isNegationOf(candidate, inner) && inner == term) {
                result = candidate;
                found = true;
                break;
              }
            }
          }
          if (!found && builder) {
            result = builder->CreateNeg(term);
          }
        }
      } else if (builder) {
        // Multi-term canonical form. Materialise it only when strictly
        // simpler than the original chain; otherwise the path solver is
        // better off receiving the unmodified value (which O2 will fold
        // later anyway).
        unsigned originalAddSubCount = countOriginalAddSubOps();
        unsigned canonicalAddSubCount =
            static_cast<unsigned>(nonConst.size()) +
            (constantTermSum != 0 ? 1u : 0u) - 1u;
        if (canonicalAddSubCount < originalAddSubCount) {
          Value* acc = nullptr;
          for (auto& [term, c] : nonConst) {
            Value* termVal = materializeTerm(term, c, ty, builder);
            if (!termVal) {
              acc = nullptr;
              break;
            }
            if (!acc) {
              acc = termVal;
            } else if (c >= 0) {
              acc = builder->CreateAdd(acc, termVal);
            } else {
              // termVal already absorbed the negation via materializeTerm,
              // so adding it produces the correct sign.
              acc = builder->CreateAdd(acc, termVal);
            }
          }
          if (acc && constantTermSum != 0) {
            acc = builder->CreateAdd(
                acc, ConstantInt::getSigned(ty, constantTermSum));
          }
          if (acc) result = acc;
        }
      }
      (void)constantTermKey;
    }
  }

  cache[V] = result;
  return result;
}

llvm::Value* deepSimplifyValue(
    Value* V, IRBuilder<InstSimplifyFolder>* builder,
    const DataLayout& DL) {
  if (!V) return V;
  DenseMap<Value*, Value*> cache;
  return deepSimplifyImpl(V, DL, builder, cache, 0);
}
// Try to resolve a symbolic branch target to a concrete address by:
// 1. Attempting LLVM ConstantFoldInstruction on the value
// 2. Attempting LLVM simplifyInstruction on the value
// Returns PATH_solved with dest set if the value folds to a constant,
// PATH_unsolved otherwise. This is intentionally conservative — it only
// succeeds when LLVM can prove the value is a single constant.
PATH_info getConstraintVal(llvm::Function* function, Value* constraint,
                           uint64_t& dest) {
  printvalue(constraint);

  // Already a constant — should have been caught by caller, but handle anyway.
  if (auto* CI = dyn_cast<ConstantInt>(constraint)) {
    dest = CI->getZExtValue();
    return PATH_solved;
  }

  auto* inst = dyn_cast<Instruction>(constraint);
  if (!inst)
    return PATH_unsolved;

  const DataLayout& DL = function->getParent()->getDataLayout();

  // Try constant folding first (cheaper, handles pure-constant operand cases).
  if (auto* folded = ConstantFoldInstruction(inst, DL)) {
    if (auto* CI = dyn_cast<ConstantInt>(folded)) {
      dest = CI->getZExtValue();
      printvalue(CI);
      return PATH_solved;
    }
  }

  // Try instruction simplification (handles identities, known-bits, etc).
  SimplifyQuery SQ(DL, inst);
  if (auto* simplified = simplifyInstruction(inst, SQ)) {
    if (auto* CI = dyn_cast<ConstantInt>(simplified)) {
      dest = CI->getZExtValue();
      printvalue(CI);
      return PATH_solved;
    }
  }

  return PATH_unsolved;
}
