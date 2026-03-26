#ifndef CUSTOMPASSES_H
#define CUSTOMPASSES_H

#include "MemoryPolicy.hpp"
#include "FileReader.hpp"
#include "Includes.h"
#include "Utils.h"
#include "llvm/IR/PassManager.h"
#include <algorithm>
#include <llvm/ADT/SmallPtrSet.h>
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
              min_offset = std::min(min_offset, val);
              max_offset = std::max(max_offset, val);
              found_any = true;
              pending.push_back({GEP, true, val});
            }
            continue;
          }
          // Non-constant offset: use KnownBits to bound the range
          auto offsetKB = computeKnownBits(OffOp, M.getDataLayout());
          uint64_t kb_min = offsetKB.getMinValue().getZExtValue();
          uint64_t kb_max = offsetKB.getMaxValue().getZExtValue();
          // Accept if the entire KnownBits range falls within stack bounds.
          if (isStackAddress(kb_min) && isStackAddress(kb_max)) {
            min_offset = std::min(min_offset, kb_min);
            max_offset = std::max(max_offset, kb_max);
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
                max_offset = std::max({max_offset, tv, fv});
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
  GEPLoadPass(Value* val, uint8_t* filebase, MemoryPolicy mempolicy)
      : mem(val), file(filebase), mempolicy(mempolicy){};

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
#endif
