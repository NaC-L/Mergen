#include "includes.h"
#include "nacibaba_opts.h"
#include "OperandUtils.h"
#include "CustomPasses.hpp"


void* file_base_g;
ZyanU8* data_g;

 
// remove this **special** global variable stuff its UGLY
void initDetections(void* file_base, ZyanU8* data) {
    file_base_g = file_base;
    data_g = data;
}


void test_optxd(Function* clonedFuncx) {
    llvm::PassBuilder passBuilder;

    
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
            return true;
        }
        return false;
    });

    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));

        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.addPass(RemovePseudoStackPass());
        modulePassManager.run(*module, moduleAnalysisManager);

        
        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);
}

void final_optpass(Function* clonedFuncx) {
    llvm::PassBuilder passBuilder;

    
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.addPass(RemovePseudoStackPass());

        modulePassManager.run(*module, moduleAnalysisManager);

        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);
}



opaque_info isOpaque(Function* function) {
    

    auto file_base = file_base_g;
    auto data = data_g;


    opaque_info result = NOT_OPAQUE;

    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    
    if (returnInst->getReturnValue() != nullptr) {
        
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

    
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());
    llvm::PassBuilder passBuilder;

#ifdef _DEVELOPMENT
    std::string Filename = "output_opaque_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    clonedFunc->print(OS);
#endif
    
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFunc->getParent();

    bool changed;
    do {
        changed = false;

        

        size_t beforeSize = module->getInstructionCount();

        

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

        modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
        
        modulePassManager.addPass(ReplaceTruncWithLoadPass());

        modulePassManager.addPass(RemovePseudoStackPass());


        auto result = modulePassManager.run(*module, moduleAnalysisManager);

#ifdef _DEVELOPMENT
        std::string Filename2 = "output_opaque_opt2.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        clonedFunc->print(OS2);
#endif

        
        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);


        
    returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator());
        
        if (returnInst->getReturnValue() != nullptr) {
            
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


ROP_info isROP(Function* function, BasicBlock& clonedBB, uintptr_t &dest) {
    

   

    auto file_base = file_base_g;
    auto data = data_g;

    ROP_info result = ROP_return;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    IRBuilder<> builder(&clonedBB);
    Value* rspvalue = GetRegisterValue(clonedBB.getContext(), builder, ZYDIS_REGISTER_RSP);
    
    if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
        int64_t rspval = constInt->getSExtValue();
        
        result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
        if (result == REAL_return) {
            return result;
        }
    }

    if (returnInst->getReturnValue() != nullptr) {
        
        llvm::Value* returnValue = returnInst->getReturnValue();
        if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(returnValue)) {
            dest = constInt->getZExtValue();
            return result;
        }
    }
    
    llvm::PassBuilder passBuilder;

    
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
            return true;
        }
        return false;
    });

    llvm::ValueToValueMapTy VMap;
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);
    std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", function->getContext());
    clonedFunctmp->removeFromParent();
    
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

        

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
        
        modulePassManager.addPass(ReplaceTruncWithLoadPass());

        modulePassManager.addPass(RemovePseudoStackPass());



        auto result = modulePassManager.run(*module, moduleAnalysisManager);

#ifdef _DEVELOPMENT
        std::string Filename2 = "output_rop_opt2.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(Filename2, EC2);
        clonedFunc->print(OS2);
#endif

        
        std::string afterOptimization;
        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);




    
    if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
        int64_t rspval = constInt->getSExtValue();
        
        result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
        if (result == REAL_return) {
            return result;
       }
    }
    returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator());
    if (returnInst->getReturnValue() != nullptr) {
        
        llvm::Value* returnValue = returnInst->getReturnValue();
        if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(returnValue)) {
            dest = constInt->getZExtValue();
        }
    }






    return result;
}


JMP_info isJOP(Function* function, uintptr_t& dest) {
    

    


    JMP_info result = JOP_jmp_unsolved;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    if (returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator())) {
        
        if (returnInst->getReturnValue() != nullptr) {
            
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

    
    destinationModule->getFunctionList().push_back(clonedFunctmp);

    Function* clonedFunc = destinationModule->getFunction(clonedFunctmp->getName());

    
    llvm::PassBuilder passBuilder;

    
    llvm::LoopAnalysisManager loopAnalysisManager;
    llvm::FunctionAnalysisManager functionAnalysisManager;
    llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
    llvm::ModuleAnalysisManager moduleAnalysisManager;

    
    passBuilder.registerModuleAnalyses(moduleAnalysisManager);
    passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
    passBuilder.registerFunctionAnalyses(functionAnalysisManager);
    passBuilder.registerLoopAnalyses(loopAnalysisManager);
    passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager, moduleAnalysisManager);

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

    passBuilder.registerPipelineParsingCallback([&](llvm::StringRef Name, llvm::ModulePassManager& MPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (Name == "gep-load-pass") {
            modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFunc->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass(file_base_g,data_g));
        

        modulePassManager.addPass(ReplaceTruncWithLoadPass());


        modulePassManager.addPass(RemovePseudoStackPass());

        auto result = modulePassManager.run(*module, moduleAnalysisManager);

        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);



#ifdef _DEVELOPMENT
    std::string Filename2 = "output_afterJMP.ll";
    std::error_code EC2;
    llvm::raw_fd_ostream OS2(Filename2, EC2);
    clonedFunc->print(OS2);
#endif
    

    
    
    if (returnInst = dyn_cast<llvm::ReturnInst>(clonedFunc->back().getTerminator() )) {
        
        if (returnInst->getReturnValue() != nullptr) {
            
            if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                dest = constInt->getZExtValue();
                result = JOP_jmp;
            }
        }
    }



    clonedFunc->eraseFromParent();
    return result;
}
