#ifndef CUSTOMPASSES_H
#define CUSTOMPASSES_H

#include "MemoryPolicy.hpp"
#include "FileReader.hpp"
#include "Includes.h"
#include "Utils.h"
#include "llvm/IR/PassManager.h"
#include <algorithm>
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
  PromotePseudoStackPass(Value* val) : mem(val){};
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

    bool hasChanged = false;
    llvm::Value* stackMemory = nullptr;

    for (auto& F : M) {
      llvm::Value* memory = mem;

      // --- Pass 1: scan all stack GEPs to find the actual offset range ---
      uint64_t min_offset = STACKP_VALUE;
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
          auto* MemOp = GEP->getOperand(GEP->getNumOperands() - 2);
          if (MemOp != memory) continue;
          auto* OffOp = GEP->getOperand(GEP->getNumOperands() - 1);

          if (auto* CI = dyn_cast<ConstantInt>(OffOp)) {
            uint64_t val = CI->getZExtValue();
            if (val < STACKP_VALUE) {
              min_offset = std::min(min_offset, val);
              max_offset = std::max(max_offset, val);
              found_any = true;
              pending.push_back({GEP, true, val});
            }
            continue;
          }
          // Non-constant offset: use KnownBits to bound the range
          auto offsetKB = computeKnownBits(OffOp, M.getDataLayout());
          auto SSKB = KnownBits::makeConstant(APInt(64, STACKP_VALUE));
          if (KnownBits::ult(offsetKB, SSKB)) {
            uint64_t kb_min = offsetKB.getMinValue().getZExtValue();
            uint64_t kb_max = offsetKB.getMaxValue().getZExtValue();
            min_offset = std::min(min_offset, kb_min);
            max_offset = std::max(max_offset, kb_max);
            found_any = true;
            pending.push_back({GEP, false, 0});
          } else if (auto* SI = dyn_cast<SelectInst>(OffOp)) {
            // SelectInst with two constant arms: check both < STACKP_VALUE
            if (isa<ConstantInt>(SI->getTrueValue()) &&
                isa<ConstantInt>(SI->getFalseValue())) {
              uint64_t tv = cast<ConstantInt>(SI->getTrueValue())->getZExtValue();
              uint64_t fv = cast<ConstantInt>(SI->getFalseValue())->getZExtValue();
              if (tv < STACKP_VALUE && fv < STACKP_VALUE) {
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
    for (auto& F : M) {
      for (auto& BB : F) {
        for (auto& I : BB) {
          if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {

            auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
            if (auto* ConstInt =
                    llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand)) {
              uint64_t constintvalue = (uint64_t)ConstInt->getZExtValue();
              if (mempolicy.isSymbolic(constintvalue)) {
                continue;
              }
              if (uint64_t offset =
                      file.address_to_mapped_address(constintvalue)) {
                for (auto* User : GEP->users()) {
                  if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(User)) {
                    // todo check if bytes are concrete/symbolic
                    llvm::Type* loadType = LoadInst->getType();
                    unsigned byteSize = loadType->getIntegerBitWidth() / 8;
                    uint64_t tempvalue;

                    file.readMemory(constintvalue, byteSize, tempvalue);

                    llvm::APInt readValue(byteSize * 8, tempvalue);
                    llvm::Constant* newVal =
                        llvm::ConstantInt::get(loadType, readValue);

                    LoadInst->replaceAllUsesWith(newVal);
                    hasChanged = true;
                  }
                }
              }
            }
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
    std::vector<llvm::Instruction*> toRemove;
    for (auto& F : M) {
      for (auto& BB : F) {
        for (auto I = BB.begin(), E = BB.end(); I != E;) {

          auto CurrentI = I++;

          if (auto* TruncInst = llvm::dyn_cast<llvm::TruncInst>(&*CurrentI)) {

            if (TruncInst->getSrcTy()->isIntegerTy(64) &&
                TruncInst->getDestTy()->isIntegerTy(32)) {

              if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(
                      TruncInst->getOperand(0))) {

                llvm::LoadInst* newLoad = new llvm::LoadInst(
                    TruncInst->getType(), LoadInst->getPointerOperand(),
                    "passload", false, LoadInst);

                TruncInst->replaceAllUsesWith(newLoad);

                toRemove.push_back(TruncInst);

                hasChanged = true;
              }
            }
          }
        }
      }
    }
    for (llvm::Instruction* Inst : toRemove) {
      Inst->eraseFromParent();
    }
    toRemove.clear();
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
class ResizeAllocatedStackPass
    : public llvm::PassInfoMixin<ResizeAllocatedStackPass> {
public:
  bool chainEnd(Instruction* inst) {
    return isa<CallInst>(inst) || isa<LoadInst>(inst) || isa<StoreInst>(inst);
  }
  void chainLook(llvm::Module& M, Instruction* GEP,
                 uint64_t& smallest_val_of_chain) {
    for (auto user : GEP->users()) {
      auto inst = cast<Instruction>(user);
      auto offset = GEP->getOperand(1);
      auto offsetKB = computeKnownBits(offset, M.getDataLayout());
      smallest_val_of_chain += offsetKB.getMinValue().getZExtValue();
      if (chainEnd(inst)) {
        return;
      }
      chainLook(M, inst, smallest_val_of_chain);
    }
  }
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    std::vector<llvm::Instruction*> toResize;
    uint64_t smallest = std::numeric_limits<uint64_t>::max();
    bool hasChanged = false;

    for (auto& F : M) {
      if (F.isDeclaration())
        continue;

      Instruction* Allocated = &(F.getEntryBlock().front());
      if (!isa<AllocaInst>(Allocated))
        continue;

      // PromotePseudoStackPass now emits byte-addressed i8 allocas.
      // This pass was designed for the legacy i128 format. Skip i8 allocas
      // since they are already correctly sized.
      auto* AI = cast<AllocaInst>(Allocated);
      if (AI->getAllocatedType()->isIntegerTy(8))
        continue;

      for (auto& BB : F) {
        for (auto& I : BB) {
          if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
            if (GEP->getOperand(0) == Allocated) {
              uint64_t smallest_val_of_chain = 0;
              chainLook(M, GEP, smallest_val_of_chain);
              smallest = std::min(smallest_val_of_chain, smallest);
              toResize.push_back(GEP);
            }
          }
        }
      }

      if (smallest != std::numeric_limits<uint64_t>::max()) {
        IRBuilder<> builder(M.getContext());
        auto allocainst = cast<AllocaInst>(Allocated);
        auto allocaType = allocainst->getAllocatedType();

        auto allocationSize =
            M.getDataLayout().getTypeAllocSize(allocaType) / 16;
        // / 16 because i128 is (i) 8 x 16
        auto newSize = allocationSize - smallest;
        Type* newType =
            ArrayType::get(Type::getInt8Ty(allocainst->getContext()), newSize);

        builder.SetInsertPoint(allocainst);
        AllocaInst* newAlloca = builder.CreateAlloca(
            newType, nullptr, allocainst->getName() + ".resized");

        allocainst->replaceAllUsesWith(newAlloca);
        allocainst->eraseFromParent();

        for (llvm::Instruction* GEPInst : toResize) {

          builder.SetInsertPoint(GEPInst);

          auto val = GEPInst->getOperand(1);

          Value* newval = builder.CreateSub(val, builder.getInt64(smallest));
          GEPInst->setOperand(1, newval);
        }

        toResize.clear();
        hasChanged = true;
      }
    }
    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};

#endif
