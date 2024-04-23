#pragma once
#ifndef GEPLoadPass_H
#define GEPLoadPass_H

#include "includes.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "OperandUtils.h"
#include "GEPTracker.h"


class RemovePseudoStackPass : public llvm::PassInfoMixin<RemovePseudoStackPass> {
public:


    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        
        Value* memory = getMemory();

        bool hasChanged = false;
        Value* stackMemory = NULL;
#ifdef _DEVELOPMENT
        std::string Filename2 = "output_before_finalopt2.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        M.print(OS2, nullptr);
#endif
        for (auto& F : M) {
            if (!stackMemory) {
                llvm::IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
                stackMemory = Builder.CreateAlloca(llvm::Type::getInt128Ty(M.getContext()), llvm::ConstantInt::get(llvm::Type::getInt128Ty(M.getContext()), STACKP_VALUE * 10), "stackmemory");
            }
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
                        
                        auto* MemoryOperand = GEP->getOperand(GEP->getNumOperands() - 2);
                        //printvalue(MemoryOperand)
                        //printvalue(memory)

                        if (memory != MemoryOperand)
                            continue; // this is a good(!) solution

                        auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
                        //printvalue(OffsetOperand)

                        if (!isa<ConstantInt>(OffsetOperand))
                            continue; // ??? also we can use knwonbits here but MEH

                        if (auto* ConstInt = llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand)) {
                            uintptr_t constintvalue = (uintptr_t)ConstInt->getZExtValue();
                            if (constintvalue < STACKP_VALUE + 100) {
                                GEP->setOperand((GEP->getNumOperands() - 2), stackMemory);
                            }
                        }
                    }
                }
            }
        }
        return hasChanged ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }
};

class GEPLoadPass : public llvm::PassInfoMixin<GEPLoadPass> {
public:

    void* file_base;
    ZyanU8* data;

    GEPLoadPass() {
        BinaryOperations::getBases(file_base, data);
    }

    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        bool hasChanged = false;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {

                        auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
                        if (auto* ConstInt = llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand)) {
                            uintptr_t constintvalue = (uintptr_t)ConstInt->getZExtValue();
                            if (uintptr_t offset = address_to_mapped_address(file_base, constintvalue)) {
                                for (auto* User : GEP->users()) {
                                    if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(User)) {
                                        llvm::Type* loadType = LoadInst->getType();


                                        unsigned byteSize = loadType->getIntegerBitWidth() / 8;
                                        uintptr_t tempvalue;

                                        std::memcpy(&tempvalue, reinterpret_cast<const void*>(data + offset), byteSize);

                                        llvm::APInt readValue(byteSize * 8, tempvalue);
                                        llvm::Constant* newVal = llvm::ConstantInt::get(loadType, readValue);


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
        return hasChanged ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }
};











class ReplaceTruncWithLoadPass : public llvm::PassInfoMixin<ReplaceTruncWithLoadPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        bool hasChanged = false;
        std::vector<llvm::Instruction*> toRemove;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto I = BB.begin(), E = BB.end(); I != E; ) {

                    auto CurrentI = I++;


                    if (auto* TruncInst = llvm::dyn_cast<llvm::TruncInst>(&*CurrentI)) {

                        if (TruncInst->getSrcTy()->isIntegerTy(64) && TruncInst->getDestTy()->isIntegerTy(32)) {

                            if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(TruncInst->getOperand(0))) {

                                llvm::LoadInst* newLoad = new llvm::LoadInst(TruncInst->getType(),
                                    LoadInst->getPointerOperand(),
                                    "passload",
                                    false,
                                    LoadInst);

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
        return hasChanged ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }
};


#endif 

