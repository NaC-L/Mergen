#ifndef CUSTOMPASSES_H
#define CUSTOMPASSES_H

#include "MemoryPolicy.hpp"
#include "FileReader.hpp"
#include "Includes.h"
#include "Utils.h"
#include "llvm/IR/PassManager.h"
#include <algorithm>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/KnownBits.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <string>

using namespace llvm;

class BasicBlockDotGraphPass
    : public llvm::PassInfoMixin<BasicBlockDotGraphPass> {
public:
  PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    std::string filename = M.getName().str() + ".dot";
    llvm::outs() << filename << "\n";
    std::error_code EC;
    raw_fd_ostream fileStream(filename, EC);
    if (EC) {
      llvm::errs() << "Could not open file: " << EC.message() << "\n";
      return llvm::PreservedAnalyses::all();
    }

    fileStream << "digraph \"" << M.getName().str() << "\" {\n";

    std::map<const BasicBlock*, std::string> bbNames;

    for (const auto& F : M) {
      for (const BasicBlock& BB : F) {
        std::string sanitizedName;

        llvm::StringRef nameRef = BB.getName();

        if (nameRef.count('-') >= 2) {
          size_t firstHyphen = nameRef.find('-');
          size_t secondHyphen = nameRef.find('-', firstHyphen + 1);

          if (secondHyphen != llvm::StringRef::npos) {
            llvm::StringRef extracted = nameRef.substr(0, secondHyphen);

            std::string extractedStr = extracted.str();

            if (!extractedStr.empty()) {
              extractedStr.pop_back();
            }

            std::replace(extractedStr.begin(), extractedStr.end(), '-', '_');

            sanitizedName = "BB" + extractedStr;
          } else {
            sanitizedName = "BBentry";
          }
        } else {
          sanitizedName = "BBentry";
        }

        bbNames[&BB] = sanitizedName;

        fileStream << "    \"" << sanitizedName << "\" [label=\""
                   << sanitizedName << "\"];\n";
      }

      for (const BasicBlock& BB : F) {
        for (const auto SI : successors(&BB)) {
          auto Succ = SI;
          fileStream << "    " << bbNames[&BB] << " -> " << bbNames[Succ]
                     << ";\n";
        }
      }
    }

    fileStream << "}\n";

    fileStream.close();
    errs() << "Generated DOT file for function: " << M.getName() << "\n";

    return PreservedAnalyses::all();
  }
};

class PromotePseudoStackPass
    : public llvm::PassInfoMixin<PromotePseudoStackPass> {
public:
  Value* mem = nullptr;
  uint64_t stackLower; // STACKP_VALUE - reserve
  uint64_t stackUpper; // STACKP_VALUE + reserve
  PromotePseudoStackPass(Value* val, uint64_t reserve)
      : mem(val),
        stackLower(reserve <= STACKP_VALUE ? STACKP_VALUE - reserve : 0),
        stackUpper(STACKP_VALUE + reserve) {
    assert(reserve <= STACKP_VALUE &&
           "reserve exceeds STACKP_VALUE; stackLower would underflow");
  }

  bool isStackAddress(uint64_t val) const {
    return val >= stackLower && val <= stackUpper;
  }

  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

    bool hasChanged = false;

    for (auto& F : M) {
      llvm::Value* memory = mem;
      llvm::Value* stackMemory = nullptr;
      // --- Pass 1: scan all stack GEPs to find the actual offset range ---
      // The stack spans both below and above STACKP_VALUE:
      //   below = locals/saved regs (frame grows downward)
      //   above = return address, shadow space, stack-passed arguments
      // We use explicit stack bounds [stackLower, stackUpper] derived from the
      // PE header's stack reserve, NOT isConcrete() — because PE image sections
      // are also concrete and would be misclassified as stack.
      uint64_t min_offset = UINT64_MAX;
      uint64_t max_offset = 0;
      bool found_any = false;
      auto getMaxAccessBytes = [&](llvm::GetElementPtrInst* GEP) -> uint64_t {
        uint64_t maxBytes = 1;
        for (auto* User : GEP->users()) {
          if (auto* LI = llvm::dyn_cast<llvm::LoadInst>(User)) {
            maxBytes = std::max(
                maxBytes,
                static_cast<uint64_t>(
                    M.getDataLayout().getTypeStoreSize(LI->getType()).getFixedValue()));
            continue;
          }
          if (auto* SI = llvm::dyn_cast<llvm::StoreInst>(User)) {
            if (SI->getPointerOperand() == GEP) {
              maxBytes = std::max(
                  maxBytes,
                  static_cast<uint64_t>(M.getDataLayout()
                                           .getTypeStoreSize(SI->getValueOperand()->getType())
                                           .getFixedValue()));
            }
          }
        }
        return maxBytes;
      };
      struct PendingGEP {
        llvm::GetElementPtrInst* gep;
        bool constant_offset;
        uint64_t const_val; // only valid when constant_offset=true
      };
      std::vector<PendingGEP> pending;

      for (auto& BB : F) {
        for (auto& I : BB) {
          auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I);
          if (!GEP) continue;
          if (GEP->getPointerOperand() != memory) continue;
          auto* OffOp = GEP->getOperand(GEP->getNumOperands() - 1);

          if (auto* CI = dyn_cast<ConstantInt>(OffOp)) {
            uint64_t val = CI->getZExtValue();
            if (isStackAddress(val)) {
              const uint64_t accessBytes = getMaxAccessBytes(GEP);
              min_offset = std::min(min_offset, val);
              max_offset =
                  std::max(max_offset, val + std::max<uint64_t>(1, accessBytes) - 1);
              found_any = true;
              pending.push_back({GEP, true, val});
            }
            continue;
          }
          // Non-constant offset: use KnownBits to bound the range
          auto offsetKB = computeKnownBits(OffOp, M.getDataLayout());
          uint64_t kb_min = offsetKB.getMinValue().getZExtValue();
          uint64_t kb_max = offsetKB.getMaxValue().getZExtValue();
          const uint64_t accessBytes = getMaxAccessBytes(GEP);
          // Accept if the entire KnownBits range falls within stack bounds.
          if (isStackAddress(kb_min) && isStackAddress(kb_max)) {
            min_offset = std::min(min_offset, kb_min);
            max_offset =
                std::max(max_offset, kb_max + std::max<uint64_t>(1, accessBytes) - 1);
            found_any = true;
            pending.push_back({GEP, false, 0});
          } else if (auto* SI = dyn_cast<SelectInst>(OffOp)) {
            // SelectInst with two constant arms: check both in stack range
            if (isa<ConstantInt>(SI->getTrueValue()) &&
                isa<ConstantInt>(SI->getFalseValue())) {
              uint64_t tv = cast<ConstantInt>(SI->getTrueValue())->getZExtValue();
              uint64_t fv = cast<ConstantInt>(SI->getFalseValue())->getZExtValue();
              if (isStackAddress(tv) && isStackAddress(fv)) {
                min_offset = std::min({min_offset, tv, fv});
                max_offset = std::max(
                    {max_offset,
                     tv + std::max<uint64_t>(1, accessBytes) - 1,
                     fv + std::max<uint64_t>(1, accessBytes) - 1});
                found_any = true;
                pending.push_back({GEP, false, 0});
              }
            }
          }
        }
      }
      if (!found_any) continue;

      // --- Create correctly-sized byte-addressed alloca instead of 22MB i128 ---
      uint64_t alloca_size = max_offset - min_offset + 1;
      if (!stackMemory) {
        llvm::IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
        stackMemory = Builder.CreateAlloca(
            llvm::Type::getInt8Ty(M.getContext()),
            Builder.getInt64(alloca_size),
            "stackmemory");
      }

      // --- Pass 2: rewrite GEPs to use the new alloca with rebased offsets ---
      for (auto& pg : pending) {
        auto* GEP = pg.gep;
        GEP->setOperand(GEP->getNumOperands() - 2, stackMemory);
        if (pg.constant_offset) {
          // Rebase constant offset relative to min_offset
          uint64_t rebased = pg.const_val - min_offset;
          GEP->setOperand(GEP->getNumOperands() - 1,
                          ConstantInt::get(Type::getInt64Ty(M.getContext()), rebased));
        } else {
          // Rebase non-constant offset with a Sub instruction
          llvm::IRBuilder<> B(GEP);
          auto* OrigOff = GEP->getOperand(GEP->getNumOperands() - 1);
          auto* Rebased = B.CreateSub(OrigOff, B.getInt64(min_offset), "stack.rebase");
          GEP->setOperand(GEP->getNumOperands() - 1, Rebased);
        }
        hasChanged = true;
      }
    }
    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};

// refactor & template for filereader
class GEPLoadPass : public llvm::PassInfoMixin<GEPLoadPass> {
public:
  Value* mem = nullptr;
  x86_64FileReader file;
  MemoryPolicy mempolicy;
  uint64_t stackLower;
  uint64_t stackUpper;
  GEPLoadPass(Value* val, uint8_t* filebase, MemoryPolicy mempolicy,
              uint64_t reserve)
      : mem(val),
        file(filebase),
        mempolicy(mempolicy),
        stackLower(reserve <= STACKP_VALUE ? STACKP_VALUE - reserve : 0),
        stackUpper(STACKP_VALUE + reserve) {
    assert(reserve <= STACKP_VALUE &&
           "reserve exceeds STACKP_VALUE; stackLower would underflow");
  }
  bool isTrackedStackAddress(uint64_t val) const {
    return val >= stackLower && val <= stackUpper;
  }

  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool hasChanged = false;
    std::vector<llvm::Instruction*> toEraseLoads;

    for (auto& F : M) {
      for (auto& BB : F) {
        for (auto& I : BB) {
          auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I);
          if (!GEP) continue;

          // Only fold GEPs rooted on the lifter's flat memory base.
          if (GEP->getPointerOperand() != mem) continue;

          auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
          auto* ConstInt =
                    llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand);
          if (!ConstInt) continue;

          uint64_t constintvalue = ConstInt->getZExtValue();
          if (isTrackedStackAddress(constintvalue)) continue;
          if (mempolicy.isSymbolic(constintvalue)) continue;

          if (!file.address_to_mapped_address(constintvalue)) continue;

          for (auto* User : GEP->users()) {
            auto* LI = llvm::dyn_cast<llvm::LoadInst>(User);
            if (!LI) continue;

            llvm::Type* loadType = LI->getType();

            // Skip non-integer loads (float, vector, pointer).
            // getIntegerBitWidth() asserts on non-integer types.
            if (!loadType->isIntegerTy()) continue;

            unsigned byteSize = loadType->getIntegerBitWidth() / 8;
            uint64_t tempvalue;

            // Skip if readMemory fails (unmapped, BSS boundary, >8-byte load).
            if (!file.readMemory(constintvalue, byteSize, tempvalue)) continue;

            llvm::APInt readValue(byteSize * 8, tempvalue);
            llvm::Constant* newVal =
                llvm::ConstantInt::get(loadType, readValue);

            LI->replaceAllUsesWith(newVal);
            toEraseLoads.push_back(LI);
            hasChanged = true;
          }
        }
      }
    }

    for (auto* Inst : toEraseLoads)
      Inst->eraseFromParent();

    // Erase GEPs that became dead after all their load users were folded.
    // Collect in a second pass to avoid invalidating the erased loads' operands.
    for (auto& F : M) {
      for (auto& BB : F) {
        for (auto it = BB.begin(); it != BB.end();) {
          auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&*it++);
          if (!GEP) continue;
          if (GEP->getPointerOperand() != mem) continue;
          if (GEP->use_empty()) {
            GEP->eraseFromParent();
            hasChanged = true;
          }
        }
      }
    }

    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};

class ReplaceTruncWithLoadPass
    : public llvm::PassInfoMixin<ReplaceTruncWithLoadPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool hasChanged = false;
    std::vector<llvm::Instruction*> toRemoveTruncs;
    llvm::SmallPtrSet<llvm::LoadInst*, 16> loadCandidates;
    for (auto& F : M) {
      for (auto& BB : F) {
        for (auto I = BB.begin(), E = BB.end(); I != E;) {

          auto CurrentI = I++;

          if (auto* TruncInst = llvm::dyn_cast<llvm::TruncInst>(&*CurrentI)) {

            // Handle any integer narrowing (e.g. i64->i32, i32->i16, i16->i8).
            // Safe on little-endian (x86): narrower load from same address reads
            // the correct low bytes.
            if (TruncInst->getSrcTy()->isIntegerTy() &&
                TruncInst->getDestTy()->isIntegerTy()) {

              if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(
                      TruncInst->getOperand(0))) {

                llvm::LoadInst* newLoad = new llvm::LoadInst(
                    TruncInst->getType(), LoadInst->getPointerOperand(),
                    "passload", false, LoadInst);

                TruncInst->replaceAllUsesWith(newLoad);

                toRemoveTruncs.push_back(TruncInst);
                loadCandidates.insert(LoadInst);

                hasChanged = true;
              }
            }
          }
        }
      }
    }
    // Erase truncs first so their operand loads lose a user.
    for (llvm::Instruction* Inst : toRemoveTruncs)
      Inst->eraseFromParent();

    // Now erase wide loads that became dead after their trunc users were removed.
    for (llvm::LoadInst* LI : loadCandidates) {
      if (LI->use_empty())
        LI->eraseFromParent();
    }

    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};

// very simple pass
/*
convert
%GEPLoadxd-5368713239- = getelementptr i8, ptr %memory, i64 5368725620
to
%GEPLoadxd-5368713239- = inttoptr i64 5368725620 to ptr
*/
class PromotePseudoMemory : public llvm::PassInfoMixin<PromotePseudoMemory> {
public:
  Value* mem = nullptr;
  PromotePseudoMemory(Value* val) : mem(val){};
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

    std::vector<llvm::Instruction*> toPromote;

    bool hasChanged = false;
    for (auto& F : M) {
      Value* memory = mem;
      for (auto& BB : F) {
        for (auto& I : BB) {
          if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
            if (GEP->getOperand(0) == memory) {
              llvm::IntToPtrInst* newPTR = new llvm::IntToPtrInst(
                  GEP->getOperand(1), GEP->getType(), GEP->getName(), GEP);

              GEP->replaceAllUsesWith(newPTR);

              toPromote.push_back(GEP);

              hasChanged = true;
            }
          }
        }
      }

      for (llvm::Instruction* Inst : toPromote) {
        Inst->eraseFromParent();
      }
      toPromote.clear();
    }
    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};


// Normalizes switch instructions that dispatch on concrete addresses back to
// logical case indices. The lifter's GEPLoadPass folds memory reads from jump
// tables into select chains / switches over concrete target addresses. This
// pass detects the pattern and rewrites the switch to use the original input
// index (0, 1, 2, ...) instead.
//
// Detected pattern:
//   %idx = add i64 %scaled_input, BASE
//   ... (select chain reading table entries)
//   switch {i32,i64} %val, label %default [
//     {i32,i64} ADDR_0, label %bb0
//     {i32,i64} ADDR_1, label %bb1  ; ADDR_1 = ADDR_0 + STRIDE
//     ...
//   ]
// Rewritten to:
//   switch i64 %original_input, label %default [
//     i64 0, label %bb0
//     i64 1, label %bb1
//     ...
//   ]
class SwitchNormalizationPass
    : public llvm::PassInfoMixin<SwitchNormalizationPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool changed = false;

    for (auto& F : M) {
      for (auto& BB : F) {
        auto* SI = llvm::dyn_cast<llvm::SwitchInst>(BB.getTerminator());
        if (!SI || SI->getNumCases() < 2) continue;

        // Collect case values and check if they form an arithmetic progression.
        llvm::SmallVector<std::pair<int64_t, llvm::BasicBlock*>, 16> cases;
        for (auto& C : SI->cases())
          cases.push_back({C.getCaseValue()->getSExtValue(), C.getCaseSuccessor()});

        // Sort by case value to find the progression.
        llvm::sort(cases, [](const auto& a, const auto& b) {
          return a.first < b.first;
        });

        // Check for arithmetic progression with constant stride.
        int64_t base = cases[0].first;
        int64_t stride = cases[1].first - base;
        if (stride <= 0) continue;

        bool isProgression = true;
        for (unsigned i = 2; i < cases.size(); ++i) {
          if (cases[i].first != base + (int64_t)i * stride) {
            isProgression = false;
            break;
          }
        }
        if (!isProgression) continue;

        // Skip if case values look like logical indices already.
        // Concrete addresses from the lifter are large (imageBase is typically
        // 0x140000000). Logical values from user code are small.
        uint64_t maxCaseVal = static_cast<uint64_t>(cases.back().first);
        if (maxCaseVal < 0x10000) continue;

        // Verify the normalization is safe: the select chain must establish
        // a 1:1 mapping from input index to switch case. If the range guard
        // says the input ranges over N values but the switch has fewer than
        // N cases, some inputs share targets and normalization would break.
        // Heuristic: walk predecessors looking for `icmp ult %input, N` and
        // check N == numCases.
        bool rangeVerified = false;
        // Quick check: if stride == 1 in the table-address domain and there
        // are exactly (maxAddr - minAddr)/tableStride + 1 cases, the mapping
        // is likely 1:1. But the safest check is via the range guard.
        // For now, skip if the switch block has a predecessor with a branch
        // on `icmp ult` whose bound doesn't match numCases.
        for (auto* Pred : llvm::predecessors(&BB)) {
          auto* BI = llvm::dyn_cast<llvm::BranchInst>(Pred->getTerminator());
          if (!BI || !BI->isConditional()) continue;
          auto* Cmp = llvm::dyn_cast<llvm::ICmpInst>(BI->getCondition());
          if (!Cmp) continue;
          // Look for icmp ult/eq pattern. The range guard is typically
          // `icmp ult %x, N` or `icmp eq (and %x, ~(N-1)), 0`.
          if (Cmp->getPredicate() == llvm::ICmpInst::ICMP_ULT) {
            if (auto* Bound = llvm::dyn_cast<llvm::ConstantInt>(Cmp->getOperand(1))) {
              if (Bound->getZExtValue() == SI->getNumCases())
                rangeVerified = true;
            }
          }
          // Also handle the `and` + `icmp eq 0` pattern used for power-of-2 ranges.
          // e.g. `(RCX & ~3) == 0` means RCX < 4.
          if (Cmp->getPredicate() == llvm::ICmpInst::ICMP_EQ) {
            if (auto* Zero = llvm::dyn_cast<llvm::ConstantInt>(Cmp->getOperand(1))) {
              if (Zero->isZero()) {
                if (auto* AndInst = llvm::dyn_cast<llvm::BinaryOperator>(Cmp->getOperand(0))) {
                  if (AndInst->getOpcode() == llvm::Instruction::And) {
                    if (auto* Mask = llvm::dyn_cast<llvm::ConstantInt>(AndInst->getOperand(1))) {
                      // The mask zeroes the low bits of the input.
                      // Count trailing zero bits to get log2(range).
                      // e.g. mask=0xFFFFFFFC -> low 2 bits cleared -> range=4.
                      uint64_t maskVal = Mask->getZExtValue();
                      // Invert and isolate: ~0xFFFFFFFC = 0x...00000003
                      // range = lowest set bit position in (mask+1)
                      // For mask with trailing zeros: range = (mask ^ (mask-1)) >> 1 + 1
                      // Simpler: count trailing zeros of ~mask, but ~mask
                      // in 64-bit has high bits set. Use countTrailingZeros on mask.
                      unsigned trailingZeros = llvm::countr_zero(maskVal);
                      if (trailingZeros > 0 && trailingZeros < 32) {
                        uint64_t rangeSize = 1ULL << trailingZeros;
                        if (rangeSize == SI->getNumCases())
                          rangeVerified = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
        if (!rangeVerified) continue;

        // Trace back the switch condition to find the original input.
        // Pattern: switch on trunc(select-chain(add(scaled_input, BASE)))
        // We need to find the original unscaled input register value.
        llvm::Value* switchCond = SI->getCondition();

        // Strip trunc if present.
        if (auto* trunc = llvm::dyn_cast<llvm::TruncInst>(switchCond))
          switchCond = trunc->getOperand(0);

        // Try to trace through the select chain to find the add instruction
        // that computes the table index: %idx = add %scaled, BASE
        // The select chain reads: icmp eq %idx, BASE+i*STRIDE; select ...
        // We need the value BEFORE the add, then normalize.
        llvm::Value* tableIndex = switchCond;

        // Walk through select chain to find the root comparison base.
        // The select chain all compare against the same %idx value.
        llvm::Value* idxValue = nullptr;
        {
          llvm::Value* v = switchCond;
          for (unsigned depth = 0; depth < 64; ++depth) {
            auto* sel = llvm::dyn_cast<llvm::SelectInst>(v);
            if (!sel) break;
            auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
            if (!cmp) break;
            idxValue = cmp->getOperand(0);
            v = sel->getFalseValue(); // walk the chain
          }
        }

        // If we found the index value, try to extract the original input.
        // Pattern: %idx = add nuw nsw i64 %mul_ea, BASE_CONST
        //          %mul_ea = and i64 %shifted, MASK
        //          %shifted = shl i64 %INPUT, LOG2_STRIDE
        llvm::Value* originalInput = nullptr;
        if (idxValue) {
          if (auto* addInst = llvm::dyn_cast<llvm::BinaryOperator>(idxValue)) {
            if (addInst->getOpcode() == llvm::Instruction::Add) {
              llvm::Value* scaledInput = addInst->getOperand(0);
              // Strip 'and' mask.
              if (auto* andInst = llvm::dyn_cast<llvm::BinaryOperator>(scaledInput)) {
                if (andInst->getOpcode() == llvm::Instruction::And)
                  scaledInput = andInst->getOperand(0);
              }
              // Strip 'shl' to get original input.
              if (auto* shlInst = llvm::dyn_cast<llvm::BinaryOperator>(scaledInput)) {
                if (shlInst->getOpcode() == llvm::Instruction::Shl)
                  originalInput = shlInst->getOperand(0);
              }
            }
          }
        }

        if (!originalInput) continue;

        // Build the normalized switch.
        llvm::IRBuilder<> B(SI);
        // Ensure the input is the right width for the switch.
        llvm::Type* switchTy = originalInput->getType();
        auto* newSwitch = B.CreateSwitch(originalInput, SI->getDefaultDest(),
                                         SI->getNumCases());

        // Map: sorted case index i -> label, with case value = i.
        for (unsigned i = 0; i < cases.size(); ++i) {
          auto* caseVal = llvm::ConstantInt::get(
              llvm::cast<llvm::IntegerType>(switchTy), i);
          newSwitch->addCase(caseVal, cases[i].second);
        }

        // Clean up the old switch and any now-dead trunc/select chain.
        llvm::Value* oldCond = SI->getCondition();
        SI->eraseFromParent();
        // If the old condition (trunc) is now dead, remove it.
        if (auto* I = llvm::dyn_cast<llvm::Instruction>(oldCond)) {
          if (I->use_empty()) I->eraseFromParent();
        }
        changed = true;
      }
    }

    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }
};

// Strips address-dependent suffixes from block and value names to produce
// deterministic IR output that is stable across rebuilds.
//
// Naming scheme after canonicalization:
//   Blocks:  entry, bb1, bb2, ... (first block is 'entry')
//   Values:  semantic prefix preserved, address suffix removed.
//            e.g. 'realadd-5368713230-' -> 'realadd'
//            Unnamed values keep LLVM's default %0, %1, etc.
class CanonicalNamingPass
    : public llvm::PassInfoMixin<CanonicalNamingPass> {

  // Strip trailing '-<digits>-' or '-<digits>' suffixes that encode addresses.
  // Examples:
  //   'realadd-5368713230-'     -> 'realadd'
  //   'real_return-5368713239-'  -> 'real_return'
  //   'previousjmp_block-0-'     -> 'previousjmp_block'
  //   'lol-15'                   -> 'lol'
  //   'jle_Condition'            -> 'jle_Condition' (no change)
  static std::string stripAddressSuffix(llvm::StringRef name) {
    // Repeatedly strip trailing '-<digits>' or '-<digits>-' groups.
    std::string s = name.str();
    while (s.size() > 1) {
      // Strip trailing '-'
      if (s.back() == '-') s.pop_back();
      if (s.empty()) break;

      // Check if trailing segment is '-<digits>'
      auto dashPos = s.rfind('-');
      if (dashPos == std::string::npos || dashPos == 0) break;

      llvm::StringRef tail(s.data() + dashPos + 1, s.size() - dashPos - 1);
      bool allDigits = !tail.empty();
      for (char c : tail)
        allDigits &= (c >= '0' && c <= '9');

      if (!allDigits) break;
      s.resize(dashPos);
    }
    return s;
  }

public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    for (auto& F : M) {
      if (F.isDeclaration()) continue;

      // Rename basic blocks.
      unsigned bbIdx = 0;
      for (auto& BB : F) {
        if (bbIdx == 0)
          BB.setName("entry");
        else
          BB.setName("bb" + llvm::Twine(bbIdx));
        ++bbIdx;
      }

      // Rename instructions that have address-derived names.
      // Instructions without names (unnamed temporaries) are left alone —
      // LLVM assigns them sequential %0, %1, etc. during printing.
      llvm::StringMap<unsigned> nameCounters;
      for (auto& BB : F) {
        for (auto& I : BB) {
          if (!I.hasName()) continue;

          std::string base = stripAddressSuffix(I.getName());
          if (base.empty()) {
            I.setName("");
            continue;
          }

          // Deduplicate: first occurrence keeps the name, subsequent get
          // a numeric suffix.
          auto& counter = nameCounters[base];
          if (counter == 0)
            I.setName(base);
          else
            I.setName(base + "." + llvm::Twine(counter));
          ++counter;
        }
      }
    }

    // This is purely cosmetic; no semantics change.
    return llvm::PreservedAnalyses::all();
  }
};
#endif
