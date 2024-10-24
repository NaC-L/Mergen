#ifndef CUSTOMPASSES_H
#define CUSTOMPASSES_H

#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"
#include "utils.h"
#include "llvm/IR/PassManager.h"
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/KnownBits.h>

class PromotePseudoStackPass
    : public llvm::PassInfoMixin<PromotePseudoStackPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

    llvm::Value* memory = getMemory();

    bool hasChanged = false;
    llvm::Value* stackMemory = NULL;
    for (auto& F : M) {
      if (!stackMemory) {
        llvm::IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
        stackMemory = Builder.CreateAlloca(
            llvm::Type::getInt128Ty(M.getContext()),
            llvm::ConstantInt::get(llvm::Type::getInt128Ty(M.getContext()),
                                   STACKP_VALUE),
            "stackmemory");
      }
      for (auto& BB : F) {
        for (auto& I : BB) {
          if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {

            // TODO: prettify here!!!
            auto* MemoryOperand = GEP->getOperand(GEP->getNumOperands() - 2);
            // printvalue(MemoryOperand)
            // printvalue(memory)

            if (memory != MemoryOperand)
              continue;

            auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
            // printvalue(OffsetOperand)

            if (isa<ConstantInt>(OffsetOperand)) {
              if (auto* ConstInt =
                      llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand)) {
                uint64_t constintvalue = (uint64_t)ConstInt->getZExtValue();
                if (constintvalue < STACKP_VALUE) {
                  GEP->setOperand((GEP->getNumOperands() - 2), stackMemory);
                }
              }
              continue;
            }
            // if OffsetOperand is not a constant:
            auto offsetKB = computeKnownBits(OffsetOperand, M.getDataLayout());
            auto StackSize = APInt(64, STACKP_VALUE);

            auto SSKB = KnownBits::makeConstant(StackSize);
            if (KnownBits::ult(offsetKB, SSKB)) {
              // minimum of offsetKB
              GEP->setOperand((GEP->getNumOperands() - 2), stackMemory);
            }
            // endif
          }
        }
      }
    }
    return hasChanged ? llvm::PreservedAnalyses::none()
                      : llvm::PreservedAnalyses::all();
  }
};

// refactor
class GEPLoadPass : public llvm::PassInfoMixin<GEPLoadPass> {
public:
  ZyanU8* data;

  GEPLoadPass() { BinaryOperations::getBases(&data); }

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
              if (uint64_t offset =
                      FileHelper::address_to_mapped_address(constintvalue)) {
                for (auto* User : GEP->users()) {
                  if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(User)) {
                    llvm::Type* loadType = LoadInst->getType();

                    unsigned byteSize = loadType->getIntegerBitWidth() / 8;
                    uint64_t tempvalue;

                    std::memcpy(&tempvalue,
                                reinterpret_cast<const void*>(data + offset),
                                byteSize);

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
  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

    std::vector<llvm::Instruction*> toPromote;
    Value* memory = getMemory();

    bool hasChanged = false;
    for (auto& F : M) {
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
