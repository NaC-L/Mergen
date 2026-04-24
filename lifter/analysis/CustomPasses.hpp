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
          // Skip GEPs that escape via a call argument: migrating them to the
          // stack alloca and then having a call use the resulting pointer
          // blocks mem2reg/SROA, leaving hundreds of dead stack stores in
          // the post-opt IR. Leave such GEPs through %memory - it is
          // already a function argument, so escaping it costs nothing.
          // Other non-load/store uses (ptrtoint, GEP-of-GEP, etc.) still
          // get migrated; rewrite_smoke samples rely on that.
          {
            bool escapesViaCall = false;
            for (auto* U : GEP->users()) {
              if (llvm::isa<llvm::CallBase>(U)) {
                escapesViaCall = true;
                break;
              }
            }
            if (escapesViaCall) continue;
          }
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
// SelectChainToSwitchPass folds chains of `icmp eq %idx, K_i; select` into a
// real `switch` instruction. Hex-Rays-style straight-line jump tables routinely
// lift to such a chain, which downstream readers (and SwitchNormalizationPass)
// cannot recognize as a dispatch.
//
// Pattern (per chain link, walking from chain head via false branch):
//   %ci = icmp eq <ty> %IDX, K_i
//   %si = select i1 %ci, <ty> V_i, <ty> %s_{i+1}
// Tail terminator: the last `false` operand is a Constant V_default.
//
// Match conditions:
//   - The chain head is the value flowing into a single PHI in the unique
//     successor of the block. The block's terminator is an unconditional br.
//   - All comparisons share the same %IDX operand.
//   - All true-branch values are Constants. The terminating false branch is
//     a Constant.
//   - Case constants are unique (no duplicate switch cases).
//   - Chain instructions have no users outside the chain or that single PHI.
//
// Rewrite:
//   - Erase the unconditional branch and the entire chain.
//   - Emit `switch %IDX, label %default [ K_i, label %case_i ... ]` in the
//     original block.
//   - Each %case_i and %default is a fresh trampoline block containing only
//     `br label %succ`, supplying its case-specific value to the join PHI.
//   - The original BB->succ PHI incoming is removed.
//
// SwitchNormalizationPass runs after this pass and rewrites the synthesized
// switch's concrete table-address case values to logical 0..N-1 indices.
class SelectChainToSwitchPass
    : public llvm::PassInfoMixin<SelectChainToSwitchPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool changed = false;
    for (auto& F : M) {
      llvm::SmallVector<llvm::BasicBlock*, 16> worklist;
      for (auto& BB : F) worklist.push_back(&BB);
      for (auto* BB : worklist) {
        if (tryFoldBlock(BB)) changed = true;
      }
    }
    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }

private:
  // Walk a select chain from `head` via false branches. On success, populates
  // idxOut, defaultOut, cases (in chain order, head-first), and chainInsts
  // (sel/cmp pairs in chain order).
  static bool collectChain(
      llvm::SelectInst* head,
      llvm::Value*& idxOut,
      llvm::Constant*& defaultOut,
      llvm::SmallVectorImpl<std::pair<llvm::ConstantInt*, llvm::Constant*>>& cases,
      llvm::SmallVectorImpl<llvm::Instruction*>& chainInsts) {
    llvm::Value* v = head;
    llvm::Value* idx = nullptr;
    llvm::BasicBlock* parent = head->getParent();
    for (unsigned depth = 0; depth < 256; ++depth) {
      auto* sel = llvm::dyn_cast<llvm::SelectInst>(v);
      if (!sel) break;
      if (sel->getParent() != parent) return false;
      auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
      if (!cmp || cmp->getParent() != parent) return false;
      if (cmp->getPredicate() != llvm::ICmpInst::ICMP_EQ) return false;

      llvm::Value* candIdx = cmp->getOperand(0);
      auto* k = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
      if (!k) {
        // Try the swapped form.
        candIdx = cmp->getOperand(1);
        k = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(0));
        if (!k) return false;
      }
      if (!idx) idx = candIdx;
      else if (idx != candIdx) return false;

      auto* tval = llvm::dyn_cast<llvm::Constant>(sel->getTrueValue());
      if (!tval) return false;

      cases.push_back({k, tval});
      chainInsts.push_back(sel);
      chainInsts.push_back(cmp);

      v = sel->getFalseValue();
    }
    auto* def = llvm::dyn_cast<llvm::Constant>(v);
    if (!def) return false;
    if (cases.size() < 2) return false;
    idxOut = idx;
    defaultOut = def;
    return true;
  }

  static bool tryFoldBlock(llvm::BasicBlock* BB) {
    auto* term = llvm::dyn_cast<llvm::BranchInst>(BB->getTerminator());
    if (!term || !term->isUnconditional()) return false;
    auto* succ = term->getSuccessor(0);

    // Find the unique PHI in succ whose BB-incoming is a SelectInst defined
    // in BB. If multiple chains feed multiple PHIs from BB, skip for safety.
    //
    // Also collect every *other* PHI in succ that has a BB-incoming so we can
    // replicate their unchanged value across the new trampoline blocks. If any
    // such sibling PHI's incoming is itself a chain instruction (i.e. the
    // chain tail or an intermediate select), we cannot safely replicate and
    // must bail — after the rewrite BB is no longer a predecessor of succ, so
    // any stale incoming referencing BB would break the IR verifier.
    llvm::PHINode* targetPhi = nullptr;
    llvm::SelectInst* head = nullptr;
    llvm::SmallVector<llvm::PHINode*, 4> siblingPhis;
    for (auto& I : *succ) {
      auto* phi = llvm::dyn_cast<llvm::PHINode>(&I);
      if (!phi) break;
      int idxIn = phi->getBasicBlockIndex(BB);
      if (idxIn < 0) continue;
      llvm::Value* incoming = phi->getIncomingValue(idxIn);
      if (auto* sel = llvm::dyn_cast<llvm::SelectInst>(incoming)) {
        if (sel->getParent() == BB) {
          if (targetPhi) return false; // multiple chain phis — ambiguous
          targetPhi = phi;
          head = sel;
          continue;
        }
      }
      siblingPhis.push_back(phi);
    }
    if (!targetPhi || !head) return false;

    llvm::Value* idx = nullptr;
    llvm::Constant* defVal = nullptr;
    llvm::SmallVector<std::pair<llvm::ConstantInt*, llvm::Constant*>, 16> cases;
    llvm::SmallVector<llvm::Instruction*, 32> chainInsts;
    if (!collectChain(head, idx, defVal, cases, chainInsts)) return false;

    // Reject duplicate case constants — a switch must have unique values.
    {
      llvm::SmallPtrSet<llvm::ConstantInt*, 16> seen;
      for (auto& c : cases) {
        if (!seen.insert(c.first).second) return false;
      }
    }

    // Verify chain instructions have no users outside the chain or targetPhi.
    llvm::SmallPtrSet<llvm::Instruction*, 32> chainSet(chainInsts.begin(),
                                                        chainInsts.end());
    for (auto* I : chainInsts) {
      for (auto* user : I->users()) {
        auto* userInst = llvm::dyn_cast<llvm::Instruction>(user);
        if (!userInst) return false;
        if (chainSet.contains(userInst)) continue;
        if (userInst == targetPhi) continue;
        return false;
      }
    }

    // If any sibling PHI's BB-incoming is a chain instruction, we cannot
    // replicate it across trampolines (it will be erased). Bail.
    for (auto* phi : siblingPhis) {
      llvm::Value* v = phi->getIncomingValueForBlock(BB);
      if (auto* I = llvm::dyn_cast<llvm::Instruction>(v)) {
        if (chainSet.contains(I)) return false;
      }
    }

    // Build trampoline blocks. Add new PHI incomings BEFORE removing the old
    // one so the PHI is never empty mid-rewrite.
    llvm::LLVMContext& Ctx = BB->getContext();
    llvm::Function* F = BB->getParent();

    llvm::BasicBlock* defaultBB =
        llvm::BasicBlock::Create(Ctx, BB->getName() + ".sc_default", F);
    llvm::BranchInst::Create(succ, defaultBB);
    targetPhi->addIncoming(defVal, defaultBB);

    llvm::SmallVector<llvm::BasicBlock*, 16> caseBBs;
    caseBBs.reserve(cases.size());
    for (auto& c : cases) {
      llvm::BasicBlock* cb = llvm::BasicBlock::Create(
          Ctx, BB->getName() + ".sc_case", F);
      llvm::BranchInst::Create(succ, cb);
      targetPhi->addIncoming(c.second, cb);
      caseBBs.push_back(cb);
    }

    // Replace BB's terminator with the dispatch switch.
    term->eraseFromParent();
    llvm::IRBuilder<> b(BB);
    auto* SI = b.CreateSwitch(idx, defaultBB, cases.size());
    for (size_t i = 0; i < cases.size(); ++i) {
      SI->addCase(cases[i].first, caseBBs[i]);
    }

    // Drop the original BB->succ PHI incoming on the target phi.
    targetPhi->removeIncomingValue(BB, /*DeletePHIIfEmpty*/ false);

    // Replicate each sibling PHI's BB-incoming across every new trampoline
    // predecessor, then drop the stale BB-incoming. Order matters: add all
    // new edges first so the PHI is never empty mid-rewrite.
    for (auto* phi : siblingPhis) {
      llvm::Value* v = phi->getIncomingValueForBlock(BB);
      phi->addIncoming(v, defaultBB);
      for (auto* cb : caseBBs) phi->addIncoming(v, cb);
      phi->removeIncomingValue(BB, /*DeletePHIIfEmpty*/ false);
    }

    // Erase the dead chain in head-first order. Each link's only remaining
    // user (head_sel via the PHI, or each link via the next select) is gone
    // by the time we get to it.
    for (auto* I : chainInsts) {
      if (I->use_empty()) I->eraseFromParent();
    }
    return true;
  }
};

class SwitchNormalizationPass
    : public llvm::PassInfoMixin<SwitchNormalizationPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool changed = false;

    for (auto& F : M) {
      // Snapshot the block list since we may add unreachable trampolines.
      llvm::SmallVector<llvm::BasicBlock*, 16> blocks;
      for (auto& BB : F) blocks.push_back(&BB);
      for (auto* BB : blocks) {
        auto* SI = llvm::dyn_cast<llvm::SwitchInst>(BB->getTerminator());
        if (!SI || SI->getNumCases() < 2) continue;

        llvm::SmallVector<std::pair<int64_t, llvm::BasicBlock*>, 16> cases;
        for (auto& C : SI->cases())
          cases.push_back({C.getCaseValue()->getSExtValue(), C.getCaseSuccessor()});

        // Skip if case values look like logical indices already.
        // Concrete addresses from the lifter are large (imageBase is typically
        // 0x140000000). Logical values from user code are small.
        uint64_t maxRawCase = 0;
        for (auto& c : cases)
          maxRawCase = std::max(maxRawCase, static_cast<uint64_t>(c.first));
        if (maxRawCase < 0x10000) continue;

        // Trace the switch operand back to the original input plus the
        // address arithmetic that produced the case values. Two shapes are
        // supported:
        //   (a) Lifter-emitted: switch trunc(select_chain(add(scaled, BASE)))
        //       where select_chain is the original ladder. We walk it to
        //       recover the icmp's left operand, which is the add.
        //   (b) Post-SelectChainToSwitchPass: the chain is gone, so the switch
        //       operand is the add directly.
        // The address arithmetic is then add(and(shl(input, LOG2_STRIDE),
        // MASK), BASE_CONST) (the and is optional).
        llvm::Value* switchCond = SI->getCondition();
        if (auto* trunc = llvm::dyn_cast<llvm::TruncInst>(switchCond))
          switchCond = trunc->getOperand(0);

        llvm::Value* idxValue = switchCond;
        {
          llvm::Value* v = switchCond;
          for (unsigned depth = 0; depth < 64; ++depth) {
            auto* sel = llvm::dyn_cast<llvm::SelectInst>(v);
            if (!sel) break;
            auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(sel->getCondition());
            if (!cmp) break;
            idxValue = cmp->getOperand(0);
            v = sel->getFalseValue();
          }
        }

        llvm::Value* originalInput = nullptr;
        int64_t addrBase = 0;
        int64_t addrStride = 0;
        // Helper: strip trunc/zext wrappers to get at the underlying value.
        auto stripIntCasts = [](llvm::Value* v) -> llvm::Value* {
          while (true) {
            if (auto* t = llvm::dyn_cast<llvm::TruncInst>(v)) {
              v = t->getOperand(0);
              continue;
            }
            if (auto* z = llvm::dyn_cast<llvm::ZExtInst>(v)) {
              v = z->getOperand(0);
              continue;
            }
            break;
          }
          return v;
        };

        if (auto* addInst = llvm::dyn_cast<llvm::BinaryOperator>(idxValue)) {
          if (addInst->getOpcode() == llvm::Instruction::Add) {
            // Try both operand orders for the constant. InstCombine canonicalizes
            // the constant to operand(1), but the lifter may hand us pre-canonical
            // shapes.
            llvm::Value* scaledInput = nullptr;
            llvm::ConstantInt* baseConst =
                llvm::dyn_cast<llvm::ConstantInt>(addInst->getOperand(1));
            if (baseConst) {
              scaledInput = addInst->getOperand(0);
            } else {
              baseConst =
                  llvm::dyn_cast<llvm::ConstantInt>(addInst->getOperand(0));
              if (baseConst) scaledInput = addInst->getOperand(1);
            }
            if (baseConst) {
              addrBase = baseConst->getSExtValue();
              if (auto* andInst =
                      llvm::dyn_cast<llvm::BinaryOperator>(scaledInput)) {
                if (andInst->getOpcode() == llvm::Instruction::And)
                  scaledInput = andInst->getOperand(0);
              }
              if (auto* shlInst =
                      llvm::dyn_cast<llvm::BinaryOperator>(scaledInput)) {
                if (shlInst->getOpcode() == llvm::Instruction::Shl) {
                  if (auto* shiftConst = llvm::dyn_cast<llvm::ConstantInt>(
                          shlInst->getOperand(1))) {
                    uint64_t shiftAmount = shiftConst->getZExtValue();
                    if (shiftAmount < 32) {
                      addrStride = 1LL << shiftAmount;
                      originalInput = shlInst->getOperand(0);
                    }
                  }
                }
              }
            }
          }
        }
        if (!originalInput || addrStride <= 0) continue;

        // Compute the input range guard once. Two predecessor shapes are
        // accepted:
        //   icmp ult %x, N            -> rangeSize = N
        //   icmp eq (and %x, MASK), 0 -> rangeSize = 1 << countr_zero(MASK)
        uint64_t rangeSize = 0;
        bool narrowMaskGuard = false;
        // The value the guard actually constrains. Width may be < originalInput.
        llvm::Value* guardedValue = nullptr;
        for (auto* Pred : llvm::predecessors(BB)) {
          auto* BI = llvm::dyn_cast<llvm::BranchInst>(Pred->getTerminator());
          if (!BI || !BI->isConditional()) continue;
          auto* Cmp = llvm::dyn_cast<llvm::ICmpInst>(BI->getCondition());
          if (!Cmp) continue;
          // BB must sit on the true edge (in-range side) of the guard. Both
          // accepted shapes have `i1 true = in range` semantics.
          if (BI->getSuccessor(0) != BB) continue;

          // Helper: the guard's compared value may be a trunc/zext of
          // originalInput. If it is narrower than originalInput, the high bits
          // of originalInput are unconstrained by this guard, so the folded-
          // default rewrite must mask those bits away before dispatching.
          auto isNarrowerThanOriginal = [&](llvm::Value* compared) {
            unsigned cw = compared->getType()->getIntegerBitWidth();
            unsigned ow = originalInput->getType()->getIntegerBitWidth();
            return cw < ow;
          };

          if (Cmp->getPredicate() == llvm::ICmpInst::ICMP_ULT) {
            auto* Bound =
                llvm::dyn_cast<llvm::ConstantInt>(Cmp->getOperand(1));
            if (!Bound) continue;
            // The compared value must be the (possibly trunc/zext-wrapped)
            // originalInput. Otherwise the guard is on a different quantity
            // and using its bound as our rangeSize is unsound.
            if (stripIntCasts(Cmp->getOperand(0)) != originalInput) continue;
            guardedValue = Cmp->getOperand(0);
            if (isNarrowerThanOriginal(Cmp->getOperand(0)))
              narrowMaskGuard = true;
            rangeSize = Bound->getZExtValue();
            break;
          }
          if (Cmp->getPredicate() == llvm::ICmpInst::ICMP_EQ) {
            auto* Zero =
                llvm::dyn_cast<llvm::ConstantInt>(Cmp->getOperand(1));
            if (!Zero || !Zero->isZero()) continue;
            auto* AndInst = llvm::dyn_cast<llvm::BinaryOperator>(Cmp->getOperand(0));
            if (!AndInst || AndInst->getOpcode() != llvm::Instruction::And)
              continue;
            auto* Mask = llvm::dyn_cast<llvm::ConstantInt>(AndInst->getOperand(1));
            if (!Mask) continue;
            if (stripIntCasts(AndInst->getOperand(0)) != originalInput) continue;
            guardedValue = AndInst->getOperand(0);
            uint64_t maskVal = Mask->getZExtValue();
            unsigned maskWidth = Mask->getType()->getIntegerBitWidth();
            unsigned trailingZeros = llvm::countr_zero(maskVal);
            if (trailingZeros == 0 || trailingZeros >= 32) continue;
            // The "narrow mask" case: high bits of originalInput above the
            // trailing-zero block are unconstrained, so `originalInput` itself
            // may hold values outside [0, 2^tz). We still get a valid logical
            // index by masking at switch time. Mark it so we emit the switch
            // on (originalInput & ((1<<tz)-1)) rather than raw originalInput.
            uint64_t widthMask =
                maskWidth >= 64 ? ~0ULL : ((1ULL << maskWidth) - 1);
            uint64_t expected =
                widthMask ^ ((1ULL << trailingZeros) - 1);
            if ((maskVal & widthMask) != expected) narrowMaskGuard = true;
            // Even with a perfectly-shaped mask, the guard only constrains the
            // low `maskWidth` bits of originalInput. If maskWidth < operand
            // width, the high bits remain unknown.
            if (isNarrowerThanOriginal(AndInst->getOperand(0)))
              narrowMaskGuard = true;
            rangeSize = 1ULL << trailingZeros;
            break;
          }
        }
        if (rangeSize == 0) continue;

        // Mode A (index-arithmetic): the case constants ARE in the same address
        // space as the lifter's index arithmetic, so each case = base + i*stride
        // for some logical i. Walking idxValue's add/and/shl recovers (base,
        // stride) and lets us emit cases with their true logical indices. This
        // also lets us promote a folded chain default (case 0 -> old default).
        //
        // Mode B (sorted-position fallback): the case constants don't fit the
        // index arithmetic but they still form an arithmetic progression among
        // themselves (e.g. switch on a chain of jump-table TARGET addresses).
        // Map the sorted i'th case to logical index i.
        bool useFoldedDefault = false;
        llvm::SmallVector<std::pair<int64_t, llvm::BasicBlock*>, 16> logicalCases;

        // Try Mode A.
        bool modeAOk = true;
        for (auto& c : cases) {
          int64_t off = c.first - addrBase;
          if (off < 0 || (off % addrStride) != 0) {
            modeAOk = false;
            break;
          }
          logicalCases.push_back({off / addrStride, c.second});
        }
        if (modeAOk) {
          llvm::sort(logicalCases, [](const auto& a, const auto& b) {
            return a.first < b.first;
          });
          for (size_t i = 1; i < logicalCases.size(); ++i) {
            if (logicalCases[i].first != logicalCases[i - 1].first + 1) {
              modeAOk = false;
              break;
            }
          }
        }
        if (modeAOk) {
          const int64_t minLogical = logicalCases.front().first;
          const int64_t maxLogical = logicalCases.back().first;
          const uint64_t numCases = logicalCases.size();
          const bool basicMatch =
              (minLogical == 0) && (rangeSize == numCases) &&
              (static_cast<uint64_t>(maxLogical + 1) == rangeSize);
          const bool foldedDefault =
              (minLogical == 1) && (rangeSize == numCases + 1) &&
              (static_cast<uint64_t>(maxLogical + 1) == rangeSize);
          if (basicMatch) {
            // Use logicalCases as-is.
          } else if (foldedDefault) {
            useFoldedDefault = true;
          } else {
            modeAOk = false;
          }
        }

        // Mode B fallback.
        if (!modeAOk) {
          logicalCases.clear();
          auto sortedCases = cases;
          llvm::sort(sortedCases, [](const auto& a, const auto& b) {
            return a.first < b.first;
          });
          int64_t apBase = sortedCases[0].first;
          int64_t apStride = sortedCases[1].first - apBase;
          if (apStride <= 0) continue;
          bool isAp = true;
          for (size_t i = 2; i < sortedCases.size(); ++i) {
            if (sortedCases[i].first != apBase + (int64_t)i * apStride) {
              isAp = false;
              break;
            }
          }
          if (!isAp) continue;
          if (rangeSize != sortedCases.size()) continue;
          for (size_t i = 0; i < sortedCases.size(); ++i)
            logicalCases.push_back({(int64_t)i, sortedCases[i].second});
        }

        // Build the normalized switch. The default switch operand is
        // `originalInput` (raw, unmasked); for the folded-default rewrite that
        // converts the original default into an `unreachable` trampoline, we
        // must guarantee unknown high bits cannot escape into that block.
        // Strategy: when narrowMaskGuard is set, use the guard's actual
        // compared value (`guardedValue`). If `guardedValue` is already
        // narrower than `originalInput` (an explicit trunc), it is exactly the
        // constrained quantity, so use it directly and key the switch type
        // off it. If `guardedValue` has the same width but the mask only
        // constrains the low bits (e.g. `(RCX & 0xFFFFFFF0) == 0`), wrap it in
        // an `and` against `(rangeSize - 1)` — only valid when rangeSize is a
        // power of 2, which is always the case for the and+eq guard form.
        // For basic-match and Mode B, the original default already handles
        // out-of-range inputs and no masking is needed.
        llvm::IRBuilder<> B(SI);
        llvm::Value* switchOperand = originalInput;
        if (useFoldedDefault && narrowMaskGuard) {
          if (guardedValue &&
              guardedValue->getType()->getIntegerBitWidth() <
                  originalInput->getType()->getIntegerBitWidth()) {
            // Trunc form (e.g. `icmp ult i32 (trunc i64 %RCX to i32), N`):
            // the trunc is already in [0, N).
            switchOperand = guardedValue;
          } else {
            // Same-width narrow-mask form. Mask trick requires power of 2.
            const bool rangeIsPow2 =
                rangeSize != 0 && (rangeSize & (rangeSize - 1)) == 0;
            if (!rangeIsPow2) continue;
            auto* opIntTy = llvm::cast<llvm::IntegerType>(
                originalInput->getType());
            switchOperand = B.CreateAnd(
                originalInput,
                llvm::ConstantInt::get(opIntTy, rangeSize - 1),
                "sw_input");
          }
        }
        llvm::Type* switchTy = switchOperand->getType();
        auto* switchIntTy = llvm::cast<llvm::IntegerType>(switchTy);
        llvm::BasicBlock* oldDefault = SI->getDefaultDest();

        // For folded-default, replace the default with an unreachable trampoline
        // and add an explicit case 0 -> oldDefault. The predecessor edge from BB
        // to oldDefault is preserved (still BB, just via case 0 now), so any PHI
        // in oldDefault that referenced BB stays valid.
        llvm::BasicBlock* newDefault = oldDefault;
        if (useFoldedDefault) {
          newDefault = llvm::BasicBlock::Create(
              SI->getContext(), BB->getName() + ".sw_unreachable",
              SI->getFunction());
          new llvm::UnreachableInst(SI->getContext(), newDefault);
        }

        const unsigned newNumCases = static_cast<unsigned>(
            logicalCases.size() + (useFoldedDefault ? 1 : 0));
        auto* newSwitch =
            B.CreateSwitch(switchOperand, newDefault, newNumCases);
        if (useFoldedDefault) {
          newSwitch->addCase(
              llvm::ConstantInt::get(switchIntTy, 0), oldDefault);
        }
        for (auto& lc : logicalCases) {
          newSwitch->addCase(
              llvm::ConstantInt::get(switchIntTy, lc.first), lc.second);
        }

        // Clean up the old switch and any now-dead trunc/select chain.
        llvm::Value* oldCond = SI->getCondition();
        SI->eraseFromParent();
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
