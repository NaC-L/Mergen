#include "includes.h"
#include "OperandUtils.h"
#include "CustomPasses.hpp"


void* file_base_g;
ZyanU8* data_g;


struct InstructionDependencyOrder {
    bool operator()(Instruction* const& a, Instruction* const& b) const {

        Function* F = a->getFunction();
        GEPStoreTracker::updateDomTree(*F);
        DominatorTree *DT = GEPStoreTracker::getDomTree();

        return ( comesBefore(b,a, *DT)  );
    }
};
 

void replaceAllUsesWithandReplaceRMap(Value* v, Value* nv, unordered_map<Value*, int> rVMap) {

    // if two values are same, we go in a infinite loop
    if (v == nv)
        return;

    auto registerV = rVMap[v];

    if (registerV) {
        if (isa<Instruction>(v)) {
            auto registerI = cast<Instruction>(v);
            SetRegisterValue(v->getContext(), registerV, v);
        }
    }


    v->replaceAllUsesWith(nv);

    v = nv;

}


// simplify Users with BFS
// because =>  
// x = add a, b 
// if we go simplify a then simplify x, then simplify b, we might miss simplifying x
// if we go simplify a, then simplify b, then simplify x we will not miss
//
// also refactor this
void simplifyUsers(Value* newValue, DataLayout& DL, unordered_map<Value*, int> flippedRegisterMap) {
    unordered_map<Value*, short > visitCount;
    unordered_set<Value*> visited;
    std::priority_queue<Instruction*, std::vector<Instruction*>, InstructionDependencyOrder> toSimplify;
    for (User* user : newValue->users()) {
        if (Instruction* userInst = dyn_cast<Instruction>(user)) {
            toSimplify.push(userInst);
        }
    }

    while (!toSimplify.empty()) {
        auto simplifyUser = toSimplify.top();
        toSimplify.pop();
        visitCount[simplifyUser]++;
        auto nsv = simplifyValueLater(simplifyUser, DL);
        visited.insert(simplifyUser);
        printvalue(simplifyUser)
        printvalue(nsv)

        if (isa<GetElementPtrInst>(simplifyUser)) {
            for (User* user : simplifyUser->users()) {
                //printvalue(user)
                if (Instruction* userInst = dyn_cast<Instruction>(user)) {
                    
                    if (visited.find(userInst) == visited.end()) { // it can try to insert max 3 times here
                        toSimplify.push(userInst);
                        visited.insert(userInst);
                        visitCount[userInst] = 0;
                    }

                }
            }
        }

        // yes return the same value very good idea definitely wont make replaceAllUsesWith loop
        if (simplifyUser == nsv) {
            continue;
        }
        // if can simplify, continue?

        // find a way to make this look not ugly, or dont. idc
        for (User* user : simplifyUser->users()) {
            //printvalue(nsv)
            //printvalue(user)
            if (Instruction* userInst = dyn_cast<Instruction>(user)) {
                //  push if not visited
                //  printvalue(userInst)

                if (visited.find(userInst) == visited.end()) {
                    //printvalue(userInst) // if we are inserting, print for 2nd time
                    toSimplify.push(userInst);
                    visited.erase(userInst);
                }
            }
        }

        //printvalue(simplifyUser, simplify)
        //printvalue(nsv, with)

        replaceAllUsesWithandReplaceRMap(simplifyUser, nsv, flippedRegisterMap);
        //simplifyUser->replaceAllUsesWith(nsv);

    }
}
PATH_info getReturnVal(llvm::Function* function, uint64_t &dest) {
    PATH_info result = PATH_unsolved;
    if (auto returnInst = dyn_cast<llvm::ReturnInst>(function->back().getTerminator())) {
        printvalue(returnInst)
            if (returnInst->getReturnValue() != nullptr) {

                if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
                    printvalue(constInt)
                        dest = constInt->getZExtValue();
                    result = PATH_solved;
                    return result;
                }
            }
    }
    return result;
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

        if (std::find(values.begin(), values.end(), temp) == values.end()) {
            values.push_back(temp); 
        }

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

        
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());

        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.addPass(RemovePseudoStackPass());
        modulePassManager.run(*module, moduleAnalysisManager);

        
        size_t afterSize = module->getInstructionCount();

        
        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);
}


// this doesnt belong in this file anymore but it also doesnt have a home...
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

    
    llvm::ModulePassManager modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);

    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        
        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());
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

        

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

        modulePassManager.addPass(GEPLoadPass());
        
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
            modulePassManager.addPass(GEPLoadPass());
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
        modulePassManager.addPass(GEPLoadPass());
        
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

        

        modulePassManager = passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());
        

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

    // this gets the last basicblock, either change this or make sure we respect it all the times
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

    auto flippedRegisterMap = flipRegisterMap();




#ifdef _DEVELOPMENT
    std::error_code EC;
    llvm::raw_fd_ostream OS(debug_filename + "_before.ll", EC);
    clonedFunc->print(OS);
#endif
    while (dest == 0) {
   

    #ifdef _DEVELOPMENT
        std::error_code EC2;
        llvm::raw_fd_ostream OS2(debug_filename + "_after.ll", EC2);
        clonedFunc->print(OS2);
    #endif



        // check if returnInst is solveable?

        
        // make this into a function?
        if (PATH_info solved = getReturnVal(function, dest)) {
            if (solved == PATH_solved) {
                return solved; 
            }
        }

        
        
        deque<llvm::Instruction*> worklist;
        std::vector<llvm::Instruction*> visited_used;

        // Start with the return instruction
        worklist.push_front(returnInst);

        while (!worklist.empty()) {
            llvm::Instruction* inst = worklist.front();
            worklist.pop_front();
            visited_used.emplace_back(inst);

            //printvalue(inst)
                for (unsigned i = 0, e = inst->getNumOperands(); i != e; ++i) {
                    llvm::Value* operand = inst->getOperand(i);
                    if (llvm::Instruction* opInst = llvm::dyn_cast<llvm::Instruction>(operand)) {
                        if (std::find(visited_used.begin(), visited_used.end(), opInst) == visited_used.end()) {
                                //printvalue(opInst)
                                worklist.push_back(opInst);
                        }
                    }
                }
        }

        Value* value_with_least_possible_values = nullptr;
        unsigned int least_possible_value_value = INT_MAX;
        KnownBits bitsof_least_possible_value(64);

        DataLayout DL(function->getParent());

        int total_user = 0;
        // find the VWLPV(value with least possible values) that builds up to the returnValue 
        for (auto I : visited_used) {

            total_user++;
            KnownBits KnownVal = analyzeValueKnownBits(I, DL);
            unsigned int possible_values = llvm::popcount(~(KnownVal.Zero | KnownVal.One).getZExtValue()) * 2;

            printvalue(I)
            
            if (!KnownVal.isConstant() && !KnownVal.hasConflict() && possible_values < least_possible_value_value && possible_values > 0) {
                least_possible_value_value = possible_values;
                value_with_least_possible_values = cast<Value>(I);
                bitsof_least_possible_value = KnownVal;
            }

            // if constant, simplify later users?
            // simplify it aswell
            if (KnownVal.isConstant() && !KnownVal.hasConflict()) {
                printvalue(I)
                auto nsv = simplifyValueLater(I, DL);
                printvalue(nsv)
                replaceAllUsesWithandReplaceRMap(I, nsv, flippedRegisterMap);
                simplifyUsers(nsv, DL, flippedRegisterMap);
            }

        }


        if (PATH_info solved = getReturnVal(function, dest)) {
            if (solved == PATH_solved) {
                return solved;
            }
        }

       //  cout << "Total user: " << total_user << "\n";
        if (least_possible_value_value == 0)
            throw("something went terribly");


        outs() << " value_with_least_possible_values: "; value_with_least_possible_values->print(outs()); outs() << "\n";  outs().flush();
        outs() << " bitsof_least_possible_value : " << bitsof_least_possible_value << "\n";  outs().flush();
        outs() << " possible values: " << least_possible_value_value << " : \n";

        auto possible_values = getPossibleValues(bitsof_least_possible_value, least_possible_value_value - 1);
        auto original_value = value_with_least_possible_values;//(*rVMap)[value_with_least_possible_values];


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
        // TODO:
        // store current state
        // select some option 
        // after that option is explored to the end, create a branch to that option, we can use jump table?
        // similar to DFS

        unsigned long long option = 0;
        cin >> option;
        auto newValue = ConstantInt::get(value_with_least_possible_values->getType(), possible_values[option]);


        
        // replace original value with the value we selected
        replaceAllUsesWithandReplaceRMap(original_value, newValue, flippedRegisterMap);
        //original_value->replaceAllUsesWith(newValue);


        // simplify later usages
        simplifyUsers(newValue, DL, flippedRegisterMap);

        SimplifyQuery SQ(DL);




     
            
        std::string Filename3 = "output_trysolve2.ll";
        std::error_code EC3;
        raw_fd_ostream OS3(Filename3, EC3);
        function->print(OS3, nullptr);
        // receive input, replace the value with received input
        // re-run program
    }
    return result;
}