#ifndef CUSTOMPASSES_H
#define CUSTOMPASSES_H

#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"
#include "llvm/IR/PassManager.h"
#include <llvm/IR/Instructions.h>

class RemovePseudoStackPass
    : public llvm::PassInfoMixin<RemovePseudoStackPass> {
  public:
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

        Value* memory = getMemory();

        bool hasChanged = false;
        Value* stackMemory = NULL;
        for (auto& F : M) {
            if (!stackMemory) {
                llvm::IRBuilder<> Builder(
                    &*F.getEntryBlock().getFirstInsertionPt());
                stackMemory = Builder.CreateAlloca(
                    llvm::Type::getInt128Ty(M.getContext()),
                    llvm::ConstantInt::get(
                        llvm::Type::getInt128Ty(M.getContext()), STACKP_VALUE),
                    "stackmemory");
            }
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP =
                            llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {

                        auto* MemoryOperand =
                            GEP->getOperand(GEP->getNumOperands() - 2);
                        // printvalue(MemoryOperand)
                        // printvalue(memory)

                        if (memory != MemoryOperand)
                            continue;

                        auto* OffsetOperand =
                            GEP->getOperand(GEP->getNumOperands() - 1);
                        // printvalue(OffsetOperand)

                        if (!isa<ConstantInt>(OffsetOperand))
                            continue; // ??? also we can use knwonbits here but
                                      // MEH

                        if (auto* ConstInt = llvm::dyn_cast<llvm::ConstantInt>(
                                OffsetOperand)) {
                            uintptr_t constintvalue =
                                (uintptr_t)ConstInt->getZExtValue();
                            if (constintvalue < STACKP_VALUE) {
                                GEP->setOperand((GEP->getNumOperands() - 2),
                                                stackMemory);
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

class GEPLoadPass : public llvm::PassInfoMixin<GEPLoadPass> {
  public:
    void* file_base;
    ZyanU8* data;

    GEPLoadPass() { BinaryOperations::getBases(&file_base, &data); }

    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        bool hasChanged = false;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP =
                            llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {

                        auto* OffsetOperand =
                            GEP->getOperand(GEP->getNumOperands() - 1);
                        if (auto* ConstInt = llvm::dyn_cast<llvm::ConstantInt>(
                                OffsetOperand)) {
                            uintptr_t constintvalue =
                                (uintptr_t)ConstInt->getZExtValue();
                            if (uintptr_t offset =
                                    FileHelper::address_to_mapped_address(
                                        file_base, constintvalue)) {
                                for (auto* User : GEP->users()) {
                                    if (auto* LoadInst =
                                            llvm::dyn_cast<llvm::LoadInst>(
                                                User)) {
                                        llvm::Type* loadType =
                                            LoadInst->getType();

                                        unsigned byteSize =
                                            loadType->getIntegerBitWidth() / 8;
                                        uintptr_t tempvalue;

                                        std::memcpy(
                                            &tempvalue,
                                            reinterpret_cast<const void*>(
                                                data + offset),
                                            byteSize);

                                        llvm::APInt readValue(byteSize * 8,
                                                              tempvalue);
                                        llvm::Constant* newVal =
                                            llvm::ConstantInt::get(loadType,
                                                                   readValue);

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

                    if (auto* TruncInst =
                            llvm::dyn_cast<llvm::TruncInst>(&*CurrentI)) {

                        if (TruncInst->getSrcTy()->isIntegerTy(64) &&
                            TruncInst->getDestTy()->isIntegerTy(32)) {

                            if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(
                                    TruncInst->getOperand(0))) {

                                llvm::LoadInst* newLoad = new llvm::LoadInst(
                                    TruncInst->getType(),
                                    LoadInst->getPointerOperand(), "passload",
                                    false, LoadInst);

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
class RemovePseudoMemory : public llvm::PassInfoMixin<RemovePseudoMemory> {
  public:
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {

        std::vector<llvm::Instruction*> toRemove;
        Value* memory = getMemory();

        bool hasChanged = false;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP =
                            llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
                        if (GEP->getOperand(0) == memory) {
                            llvm::IntToPtrInst* newPTR = new llvm::IntToPtrInst(
                                GEP->getOperand(1), GEP->getType(),
                                GEP->getName(), GEP);

                            GEP->replaceAllUsesWith(newPTR);

                            toRemove.push_back(GEP);

                            hasChanged = true;
                        }
                    }
                }
            }

            for (llvm::Instruction* Inst : toRemove) {
                Inst->eraseFromParent();
            }
            toRemove.clear();
        }
        return hasChanged ? llvm::PreservedAnalyses::none()
                          : llvm::PreservedAnalyses::all();
    }
};

#endif
