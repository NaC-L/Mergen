#include "includes.h"
#include "OperandUtils.h"
#include "CustomPasses.hpp"


void* file_base_g;
ZyanU8* data_g;

 
// remove this **special** global variable stuff its UGLY and dumb
void initDetections(void* file_base, ZyanU8* data) { 
    file_base_g = file_base;
    data_g = data;
}

// https://github.com/llvm/llvm-project/blob/30f6eafaa978b4e0211368976fe60f15fa9f0067/llvm/unittests/Support/KnownBitsTest.h#L38
/* ex:
KnownBits Known1;
vector<APInt> possiblevalues;
ForeachNumInKnownBits(Known1, [&](APInt Value1) { possiblevalues.push_back(Value1); });
*/
template <typename FnTy>
void ForeachNumInKnownBits(const KnownBits& Known, FnTy Fn) {
    unsigned Bits = Known.getBitWidth();
    unsigned Max = 1 << Bits;
    for (unsigned N = 0; N <= Max; ++N) {
        APInt Num(Bits, N);
        if ((Num & Known.Zero) != 0 || (~Num & Known.One) != 0) {
            continue;
        }

        Fn(Num);
    }
}

std::vector<llvm::APInt> getPossibleValues(const llvm::KnownBits& known, unsigned max_unknown) {
    llvm::APInt base = known.One;  
    llvm::APInt unknowns = ~(known.Zero | known.One);  
    unsigned numBits = known.getBitWidth();  

    std::vector<llvm::APInt> values;

    llvm::APInt combo(unknowns.getBitWidth(), 0);  
    for (uint64_t i = 0; i < (1ULL << max_unknown); ++i) {
        llvm::APInt temp = base;
        for (unsigned j = 0, currentBit = 0; j < numBits; ++j) {
            if (unknowns[j]) {  
                temp.setBitVal(j, (i >> currentBit) & 1);  
                currentBit++;
            }
        }
        values.push_back(temp);
    }

    return values;
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
    

#ifdef _DEVELOPMENT
    std::string Filename = "output_ret_noopt.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);
    function->print(OS);
#endif

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



// this is not really needed anymore except for debugging purposes. 
// we can merge isROP with isJOP, maybe merge and pass a string so it will know what to save the debug file as

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


ValueMap<const Value*, Value*> mapHoldValues;


llvm::ValueToValueMapTy* flipVMap(const ValueToValueMapTy& VMap) {
    ValueToValueMapTy* RevMap = new llvm::ValueToValueMapTy;
    for (const auto& pair : VMap) {
        (*RevMap)[pair.second] = const_cast<Value*>(pair.first);
    }
    return RevMap;
}


PATH_info solvePath(Function* function, uintptr_t& dest, string debug_filename) {





    PATH_info result = PATH_unsolved;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator());

    if (returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator())) {

        if (returnInst->getReturnValue() != nullptr) {

            if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                dest = constInt->getZExtValue();
                result = PATH_solved;
                return result;
            }
        }
    }

    llvm::ValueToValueMapTy VMap;
    llvm::Function* clonedFunctmp = llvm::CloneFunction(function, VMap);

    ValueToValueMapTy* rVMap = flipVMap(VMap);
    auto flippedRegisterMap = flipRegisterMap();
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
            modulePassManager.addPass(GEPLoadPass(file_base_g, data_g));
            return true;
        }
        return false;
    });


    llvm::Module* module = clonedFunc->getParent();


#ifdef _DEVELOPMENT
    std::error_code EC;
    llvm::raw_fd_ostream OS(debug_filename + "_before.ll", EC);
    clonedFunc->print(OS);
#endif
    while (dest == 0) {
    /*
    bool changed = false;
        do {
            changed = false;

            size_t beforeSize = module->getInstructionCount();



            modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
            modulePassManager.addPass(GEPLoadPass(file_base_g, data_g));


            modulePassManager.addPass(ReplaceTruncWithLoadPass());


            modulePassManager.addPass(RemovePseudoStackPass());

            auto result = modulePassManager.run(*module, moduleAnalysisManager);

            size_t afterSize = module->getInstructionCount();


            if (beforeSize != afterSize) {
                changed = true;
            }

        } while (changed);
        */


    #ifdef _DEVELOPMENT
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(debug_filename + "_after.ll", EC2);
        clonedFunc->print(OS2);
    #endif




        if (returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator())) {

            if (returnInst->getReturnValue() != nullptr) {

                if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                    dest = constInt->getZExtValue();
                    result = PATH_solved;
                    clonedFunc->eraseFromParent();
                    return result;
                }
            }
        }
        //clonedFunc->print(outs());
        std::set<llvm::Instruction*> worklist;
        std::set<llvm::Instruction*> visited_used;

        // Start with the return instruction
        worklist.insert(returnInst);

        while (!worklist.empty()) {
            llvm::Instruction* inst = *worklist.begin();
            worklist.erase(worklist.begin());
            visited_used.insert(inst);


            for (unsigned i = 0, e = inst->getNumOperands(); i != e; ++i) {
                llvm::Value* operand = inst->getOperand(i);
                if (llvm::Instruction* opInst = llvm::dyn_cast<llvm::Instruction>(operand)) {
                    if (visited_used.find(opInst) == visited_used.end()) {
                        worklist.insert(opInst);
                    }
                }
            }
        }

        Value* value_with_least_possible_values = nullptr;
        unsigned int least_possible_value_value = INT_MAX;
        KnownBits bitsof_least_possible_value(64);

        DataLayout DL(function->getParent());

        for (auto I : visited_used) {
            KnownBits KnownVal = analyzeValueKnownBits(I, DL);
            unsigned int possible_values = llvm::popcount(~(KnownVal.Zero | KnownVal.One).getZExtValue()) + 1;

            if (!KnownVal.isConstant() && !KnownVal.hasConflict() && possible_values < least_possible_value_value) {
                least_possible_value_value = possible_values;
                value_with_least_possible_values = cast<Value>(I);
                bitsof_least_possible_value = KnownVal;
            }

        }
        
        printvalueforce(value_with_least_possible_values)
        printvalueforce2(bitsof_least_possible_value)
            outs() << " possible values: " << least_possible_value_value << " : \n";
        auto possible_values = getPossibleValues(bitsof_least_possible_value, least_possible_value_value - 1);
        auto original_value = value_with_least_possible_values;//(*rVMap)[value_with_least_possible_values];

        if (isa<Value>(original_value))
            printvalueforce(original_value);

        unsigned max_possible_values = possible_values.size();
        for (unsigned i = 0; i < max_possible_values; i++) {
            outs() << i <<"-) v : " << possible_values[i] << "\n";
        }
        
        // print an optimized version? 
        std::string Filename = "output_trysolve.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        function->print(OS, nullptr);

        cout << "\nWhich option do you select? ";
        // TODO: implement something to remember the choice
        unsigned long long option = 0;
        cin >> option;
        auto newValue = ConstantInt::get(value_with_least_possible_values->getType(), possible_values[option]);


        

        original_value->replaceAllUsesWith(newValue);
        
        // now make this loooooooooooooppppp
        for (auto user : newValue->users()) {
            printvalue(user)
            auto nsv = simplifyValueLater(user, DL);
            printvalue(nsv)
            // yes return the same value very good idea definitely doesnt break anything
            if (user != nsv)
                user->replaceAllUsesWith(nsv);

        }

        SimplifyQuery SQ(DL);


     
            
        std::string Filename3 = "output_trysolve2.ll";
        std::error_code EC3;
        raw_fd_ostream OS3(Filename3, EC3);
        function->print(outs());
        // receive input, replace the value with received input
        // re-run program
    }
    delete rVMap;
    clonedFunc->eraseFromParent();
    return result;
}