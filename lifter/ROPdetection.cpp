#include "includes.h"
#include "nacibaba_opts.h"
#include "OperandUtils.h"


void* file_base_g;
ZyanU8* data_g;

#pragma once
#ifndef GEPLoadPass_H
#define GEPLoadPass_H

#include "includes.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"


class RemovePseudoStackPass : public llvm::PassInfoMixin<RemovePseudoStackPass> {
public:

 
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        // %stackmemory = alloca i128, i128 STACKP_VALUE
        // insert %stackmemory as first inst
        // if load is < STACKP_VALUE
        //     replace %memory with %stackmemory
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
                        // Assuming the offset is the last operand
                        auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
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

    // replace(?) if section is in --> IMAGE_SCN_MEM_EXECUTE
    // replace if section is in --> IMAGE_SCN_MEM_READ
    // dont replace if section is in --> IMAGE_SCN_MEM_WRITE
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        bool hasChanged = false;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto& I : BB) {
                    if (auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
                        // Assuming the offset is the last operand
                        auto* OffsetOperand = GEP->getOperand(GEP->getNumOperands() - 1);
                        if (auto* ConstInt = llvm::dyn_cast<llvm::ConstantInt>(OffsetOperand)) {
                            uintptr_t constintvalue = (uintptr_t)ConstInt->getZExtValue();
                            if (uintptr_t offset = address_to_mapped_address(file_base_g, constintvalue)) {
                                for (auto* User : GEP->users()) {
                                    if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(User)) {
                                        llvm::Type* loadType = LoadInst->getType();

                                        // Read the value from the address
                                        unsigned byteSize = loadType->getIntegerBitWidth() / 8;
                                        uintptr_t tempvalue;
                                        // Replace with actual address fetching logic
                                        std::memcpy(&tempvalue, reinterpret_cast<const void*>(data_g + offset), byteSize);

                                        llvm::APInt readValue(byteSize * 8, tempvalue);
                                        llvm::Constant* newVal = llvm::ConstantInt::get(loadType, readValue);

                                        // Replace the load instruction
                                        LoadInst->replaceAllUsesWith(newVal);
                                        hasChanged = true;
                                    }
                                }
                            }
                             
                            // if not in binary & never referenced before, return ConstantInt::get(getIntSize(byteSize, context), 0);
                        }
                    }
                }
            }
        }
        return hasChanged ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all() ;
    }
};


// here because this case is not properly optimized
// store i64 %arg, ptr yyy
// store i32 constant, ptr yyy
// %x = load i64, ptr %yyy
// %x1 = trunc i64 %x to i32
// this case it should've been
// %x1 = constant, however it doesnt properly optimize, so this is the fix

// while we are doing that, we can just if something is not stored just replace it with 0?
class ReplaceTruncWithLoadPass : public llvm::PassInfoMixin<ReplaceTruncWithLoadPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
        bool hasChanged = false;
        std::vector<llvm::Instruction*> toRemove;
        for (auto& F : M) {
            for (auto& BB : F) {
                for (auto I = BB.begin(), E = BB.end(); I != E; ) {
                    // Use a temporary iterator to safely remove instructions
                    auto CurrentI = I++;

                    // Check for a trunc instruction
                    if (auto* TruncInst = llvm::dyn_cast<llvm::TruncInst>(&*CurrentI)) {
                        // Check if it truncates from i64 to i32
                        if (TruncInst->getSrcTy()->isIntegerTy(64) && TruncInst->getDestTy()->isIntegerTy(32)) {
                            // Check if the operand of trunc is a load instruction
                            if (auto* LoadInst = llvm::dyn_cast<llvm::LoadInst>(TruncInst->getOperand(0))) {
                                // Create a new load instruction for trunc size
                                llvm::LoadInst* newLoad = new llvm::LoadInst(TruncInst->getType(),
                                    LoadInst->getPointerOperand(),
                                    "passload",
                                    false,
                                    LoadInst);
                                // Replace uses of the trunc instruction with the new load
                                TruncInst->replaceAllUsesWith(newLoad);
                                // Remove the old trunc instruction
                                toRemove.push_back(TruncInst);
                                // Update the flag
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


#endif // GEPLoadPass_H

void initDetections(void* file_base, ZyanU8* data) {
    file_base_g = file_base;
    data_g = data;
}



// detects if RSP matches the starting value of RSP
// normal function:
// 
// -- rsp = 0xffff
// push ecx 0xfff8
// ...etc...
// pop ecx  0xffff
// (before ret rsp = 0xffff)
// ret      
// 
// fake ret/function
// 
// -- rsp = 0xffff
// push ecx 0xfff8
// ...etc...
// pop ecx  0xffff
// push (next_handler) 0xfff8
// (before ret rsp = 0xfff8) 
// ret 
//

// basically apply bunch of optimizations and compare RSP
bool doesReturnRsp(Function* clonedFunc, BasicBlock& clonedBB, void* file_base, ZyanU8* data) {
    //create clone of module/function then analyze it.
    file_base_g = file_base;
    data_g = data;

    if (llvm::isa<llvm::ReturnInst>(clonedBB.getTerminator())) {


        if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(clonedBB.getTerminator()->getOperand(0))) {
            return constInt->getZExtValue() == 18446744073709551600;
        }

    }

    auto module = clonedFunc->getParent();
    auto FPM = std::make_unique<legacy::FunctionPassManager>(module);

    FPM.get()->add(createEarlyCSEPass(true));

    FPM.get()->add(create_nacibaba_replace_load_with_store_pass());

    FPM.get()->add(createEarlyCSEPass(true));

    FPM.get()->add(create_nacibaba_replace_load_from_memory(file_base, data));

    FPM.get()->add(createEarlyCSEPass(true));

    FPM.get()->add(create_nacibaba_replace_load_with_store_pass());

    FPM.get()->add(createInstructionCombiningPass());
    FPM.get()->add(createInstSimplifyLegacyPass());
    FPM.get()->add(createConstantHoistingPass());
    FPM.get()->add(createEarlyCSEPass(true));
    FPM.get()->add(createDeadCodeEliminationPass());


    FPM.get()->add(create_nacibaba_replace_load_from_memory(file_base, data));


    FPM.get()->add(createInstructionCombiningPass());

    FPM.get()->add(createInstSimplifyLegacyPass());
    FPM.get()->add(createConstantHoistingPass());

    FPM.get()->add(createEarlyCSEPass(true));
    FPM.get()->add(createDeadCodeEliminationPass());
    //FPM.get()->add(CreateIntToPtrStackDSEPass());

    // create a pass that acatually works to promote memory to register
    // basically search for loads, if we stored a value to that load replace that value
    // problem 1:
    // multiple branches
    // we should fix control flow, then if we get the condition, since its SSA we can use the condition for branches and we create a select.
    //

    FPM.get()->doInitialization();
    FPM.get()->run(*clonedFunc);
    FPM.get()->doFinalization();
    bool result;

    // Check if the instruction is a return instruction
    if (llvm::isa<llvm::ReturnInst>(clonedBB.getTerminator())) {


        if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(clonedBB.getTerminator()->getOperand(0))) {
            return constInt->getZExtValue() == 18446744073709551600;
        }

    }
    


    // after analysis
    return false;
}


//testing stuff......
void test_optxd(Function* clonedFuncx) {
    llvm::PassBuilder passBuilder;

    // Create a new module analysis manager
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    // Register the analysis managers with the PassBuilder
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    // Create the module pass manager
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass());
            return true;
        }
        return false;
    });

    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        // Build and run the optimization pipeline
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());

        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.run(*module, moduleAnalysisManager);

        
        size_t afterSize = module->getInstructionCount();

        // Check if the module has changed
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);
}

void final_optpass(Function* clonedFuncx) {
    llvm::PassBuilder passBuilder;

    // Create a new module analysis manager
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    // Register the analysis managers with the PassBuilder
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    // Create the module pass manager
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass());
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        // Build and run the optimization pipeline
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());
        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.addPass(RemovePseudoStackPass());

        modulePassManager.run(*module, moduleAnalysisManager);

        size_t afterSize = module->getInstructionCount();

        // Check if the module has changed
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);
}


// check if the flag is a constant
opaque_info isOpaque(Function* function) {
    //create clone of module/function then analyze it.

    auto file_base = file_base_g;
    auto data = data_g;


    opaque_info result = NOT_OPAQUE;

    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    // Assuming you want to check the return value of the ReturnInst
    if (returnInst->getReturnValue() != nullptr) {
        // Check if the return value is a constant integer
        if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
            if (constInt->getZExtValue() == 1) {
                result = OPAQUE_TRUE;
                return result;
            }
            else if (constInt->getZExtValue() == 0) {
                result = OPAQUE_FALSE;
                return result;
            }
        }
    }

    llvm::ValueToValueMapTy VMap;
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", function->getContext());
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());
    llvm::PassBuilder passBuilder;

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    clonedFunc->print(OS);
#endif
    // Create a new module analysis manager
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    // Register the analysis managers with the PassBuilder
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    // Create the module pass manager
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass());
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFunc->getParent();

    bool changed;
    do {
        changed = false;

        

        size_t beforeSize = module->getInstructionCount();

        // Build and run the optimization pipeline

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(IPSCCPPass());
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(ReassociatePass()));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(DSEPass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(AggressiveInstCombinePass()));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(GVNPass()));

        modulePassManager.addPass(GEPLoadPass());
        
        modulePassManager.addPass(ReplaceTruncWithLoadPass());



        auto result = modulePassManager.run(*module, moduleAnalysisManager);

#ifdef _DEVELOPMENT
        std::string Filename2 = "output_opaque_opt2.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        clonedFunc->print(OS2);
#endif

        
        size_t afterSize = module->getInstructionCount();

        // Check if the module has changed
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);


        
    returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator());
        // Assuming you want to check the return value of the ReturnInst
        if (returnInst->getReturnValue() != nullptr) {
            // Check if the return value is a constant integer
            if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                if (constInt->getZExtValue() == 1) {
                    result = OPAQUE_TRUE;
                }
                else if (constInt->getZExtValue() == 0) {
                    result = OPAQUE_FALSE;
                }
            }
        }

    return result;
}


// doesReturnRsp, but zesty
ROP_info isROP(Function* function, BasicBlock& clonedBB, uintptr_t &dest) {
    //create clone of module/function then analyze it.

   

    auto file_base = file_base_g;
    auto data = data_g;

    ROP_info result = ROP_return;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    IRBuilder<> builder(&clonedBB);
    Value* rspvalue = GetRegisterValue(clonedBB.getContext(), builder, ZYDIS_REGISTER_RSP);
    // Check if the integer operand is a constant integer
    if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
        int64_t rspval = constInt->getSExtValue();
        //cout << "rspval = " << rspval << "\n";
        result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
        if (result == REAL_return) {
            return result;
        }
    }

    if (returnInst->getReturnValue() != nullptr) {
        // Get the value that is being returned
        llvm::Value* returnValue = returnInst->getReturnValue();
        if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(returnValue)) {
            dest = constInt->getZExtValue();
            return result;
        }
    }
    // instead of passing function, lets pass a new module because this optimization shit only works with the module now
    llvm::PassBuilder passBuilder;

    // Create a new module analysis manager
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    // Register the analysis managers with the PassBuilder
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    // Create the module pass manager
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass());
            return true;
        }
        return false;
    });

    llvm::ValueToValueMapTy VMap;
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", function->getContext());
    clonedFunctmp->removeFromParent();
    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);
    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());
    llvm::Module* module = clonedFunc->getParent();

#ifdef _DEVELOPMENT
    std::string Filename = "output_ret_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    clonedFunc->print(OS);
#endif
    bool changed;

    do {

        bool haschanged = false;
        changed = false;

        
        size_t beforeSize = module->getInstructionCount();

        // Build and run the optimization pipeline

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(IPSCCPPass());
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(ReassociatePass()));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(DSEPass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(AggressiveInstCombinePass(  )));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(GVNPass()));
        modulePassManager.addPass(GEPLoadPass());
        
        modulePassManager.addPass(ReplaceTruncWithLoadPass());




        auto result = modulePassManager.run(*module, moduleAnalysisManager);

#ifdef _DEVELOPMENT
        std::string Filename2 = "output_rop_opt2.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        clonedFunc->print(OS2);
#endif

        
        std::string afterOptimization;
        size_t afterSize = module->getInstructionCount();

        // Check if the module has changed
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);




    // is this needed anymore? rsp is (almost) always a constant
    if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
        int64_t rspval = constInt->getSExtValue();
        //cout << "rspval = " << rspval << "\n";
        result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
        if (result == REAL_return) {
            return result;
       }
    }
    returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator());
    if (returnInst->getReturnValue() != nullptr) {
        // Get the value that is being returned
        llvm::Value* returnValue = returnInst->getReturnValue();
        if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(returnValue)) {
            dest = constInt->getZExtValue();
        }
    }






    return result;
}

// is a real JOP or a switch case or smt?
JMP_info isJOP(Function* function, uintptr_t& dest) {
    //create clone of module/function then analyze it.

    // check to add if we already know the result


    JMP_info result = REAL_jmp;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    if (returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator())) {
        // Assuming you want to check the return value of the ReturnInst
        if (returnInst->getReturnValue() != nullptr) {
            // Check if the return value is a constant integer
            if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                dest = constInt->getZExtValue();
                result = JOP_jmp;
                return result;
            }
        }
    }

    llvm::ValueToValueMapTy VMap;
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", function->getContext());
    clonedFunctmp->removeFromParent();

    // Add the cloned function to the destination module
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());

    // instead of passing function, lets pass a new module because this optimization shit only works with the module now
    llvm::PassBuilder passBuilder;

    // Create a new module analysis manager
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    // Register the analysis managers with the PassBuilder
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    // Create the module pass manager
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass());
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFunc->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        // Build and run the optimization pipeline

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(IPSCCPPass());
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(SROAPass(SROAOptions::PreserveCFG)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(InstCombinePass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(ReassociatePass()));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(DSEPass()));

        modulePassManager.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(AggressiveInstCombinePass()));
        modulePassManager.addPass(createModuleToFunctionPassAdaptor(GVNPass()));
        modulePassManager.addPass(GEPLoadPass());
        

        modulePassManager.addPass(ReplaceTruncWithLoadPass());



        auto result = modulePassManager.run(*module, moduleAnalysisManager);

        size_t afterSize = module->getInstructionCount();

        // Check if the module has changed
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);



    //clonedFunc->print(outs());

    //we need to modify here when adding branches
    //maybe we add metadata to return instruction and search it?
    if (returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator() )) {
        // Assuming you want to check the return value of the ReturnInst
        if (returnInst->getReturnValue() != nullptr) {
            // Check if the return value is a constant integer
            if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                dest = constInt->getZExtValue();
                result = JOP_jmp;
            }
        }
    }


#ifdef _DEVELOPMENT
    std::string Filename2 = "output_afterJMP.ll";
    std::error_code EC2;
    llvm::raw_fd_ostream OS2(Filename2, EC2);
    clonedFunc->print(OS2);
#endif

    clonedFunc->eraseFromParent();
    return result;
}
