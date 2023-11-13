#include "includes.h"
#include "nacibaba_opts.h"
#include "OperandUtils.h"

LPVOID file_base_g;
ZyanU8* data_g;

void initDetections(LPVOID file_base, ZyanU8* data) {
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
bool doesReturnRsp(Function* clonedFunc, BasicBlock& clonedBB, LPVOID file_base, ZyanU8* data) {
    //create clone of module/function then analyze it.
    file_base_g = file_base;
    data_g = data;

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
    LPVOID file_base = file_base_g;
    ZyanU8* data = data_g;
        //create clone of module/function then analyze it.
        auto module = clonedFuncx->getParent();
        auto FPM = std::make_unique<legacy::FunctionPassManager>(module);
      
        FPM.get()->add(create_nacibaba_replace_load_with_store_pass());
        FPM.get()->add(createReassociatePass());
        FPM.get()->add(createSROAPass());

        FPM.get()->add(createInstSimplifyLegacyPass());
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createLowerConstantIntrinsicsPass());
        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createPromoteMemoryToRegisterPass(true));
        FPM.get()->add(createInstructionCombiningPass());
        FPM.get()->add(createInstSimplifyLegacyPass());

        FPM.get()->add(createConstantHoistingPass());
        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createMergedLoadStoreMotionPass());
        FPM.get()->add(createPromoteMemoryToRegisterPass(true));
        FPM.get()->add(createInstructionCombiningPass());    // Do simple "peephole" optimizations and bit-twiddling optzns.
        FPM.get()->add(createReassociatePass());             // Reassociate expressions.
        //FPM.get()->add(createGVNPass());                     // Eliminate common subexpressions.
        //FPM.get()->add(createCFGSimplificationPass());       // Simplify the control flow graph (deleting unreachable blocks, etc).

        FPM.get()->add(create_nacibaba_replace_load_with_store_pass());
        FPM.get()->add(createSROAPass());




        FPM.get()->add(createInstSimplifyLegacyPass());
        FPM.get()->add(createConstantHoistingPass());

        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createMergedLoadStoreMotionPass());

        FPM.get()->add(create_nacibaba_replace_load_from_memory(file_base, data));
            
            


        FPM.get()->doInitialization();
        FPM.get()->run(*clonedFuncx);
        FPM.get()->doFinalization();

        /*
        FunctionPassManager newFPM;
        newFPM.addPass(DCEPass());
        FunctionAnalysisManager FAM;
        PassBuilder PB;
        PB.registerFunctionAnalyses(FAM);
        newFPM.run(*clonedFuncx, FAM);
        */
}

// lol idk, i got frustrated
void final_optpass(Function* clonedFuncx) {
    LPVOID file_base = file_base_g;
    ZyanU8* data = data_g;
    //create clone of module/function then analyze it.
    auto module = clonedFuncx->getParent();
    auto FPM = std::make_unique<legacy::FunctionPassManager>(module);

    bool isModified = true;

    unsigned running = 0;

    while (isModified && running < 20) {

        FPM.get()->add(create_nacibaba_replace_load_with_store_pass_final());
        FPM.get()->add(createReassociatePass());
        FPM.get()->add(createSROAPass());

        FPM.get()->add(createInstSimplifyLegacyPass());
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createLowerConstantIntrinsicsPass());
        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createPromoteMemoryToRegisterPass(true));
        FPM.get()->add(createInstructionCombiningPass());
        FPM.get()->add(createInstSimplifyLegacyPass());

        FPM.get()->add(createConstantHoistingPass());
        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createMergedLoadStoreMotionPass());
        FPM.get()->add(createPromoteMemoryToRegisterPass(true));
        FPM.get()->add(createInstructionCombiningPass());    // Do simple "peephole" optimizations and bit-twiddling optzns.
        FPM.get()->add(createReassociatePass());             // Reassociate expressions.
        //FPM.get()->add(createGVNPass());                     // Eliminate common subexpressions.
        //FPM.get()->add(createCFGSimplificationPass());       // Simplify the control flow graph (deleting unreachable blocks, etc).

        FPM.get()->add(create_nacibaba_replace_load_with_store_pass_final());
        FPM.get()->add(createSROAPass());




        FPM.get()->add(createInstSimplifyLegacyPass());
        FPM.get()->add(createConstantHoistingPass());

        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createMergedLoadStoreMotionPass());

        FPM.get()->add(create_nacibaba_replace_load_from_memory(file_base, data));


        FPM.get()->add(createInstructionCombiningPass());

        FPM.get()->add(createInstSimplifyLegacyPass());
        FPM.get()->add(createConstantHoistingPass());

        FPM.get()->add(createEarlyCSEPass(true));
        FPM.get()->add(createDeadCodeEliminationPass());
        FPM.get()->add(createMergedLoadStoreMotionPass());
        /**/



        FPM.get()->doInitialization();
        isModified = FPM.get()->run(*clonedFuncx);
        FPM.get()->doFinalization();

        running++;
        cout << endl << "running: " << running << "\n";
    }

    /*
    FunctionPassManager newFPM;
    newFPM.addPass(DCEPass());
    FunctionAnalysisManager FAM;
    PassBuilder PB;
    PB.registerFunctionAnalyses(FAM);
    newFPM.run(*clonedFuncx, FAM);
    */
}


// check if the flag is a constant
opaque_info isOpaque(Function* clonedFunc , BasicBlock& clonedBB) {
    //create clone of module/function then analyze it.

    auto file_base = file_base_g;
    auto data = data_g;

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

    // create a pass that acatually works to promote memory to register
    // basically search for loads, if we stored a value to that load replace that value
    // problem 1:
    // multiple branches
    // we should fix control flow, then if we get the condition, since its SSA we can use the condition for branches and we create a select.
    //

    FPM.get()->doInitialization();
    FPM.get()->run(*clonedFunc);
    FPM.get()->doFinalization();


    opaque_info result = NOT_OPAQUE;
    //clonedFunc->print(outs());
        llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(clonedBB.getTerminator());

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
ROP_info isROP(Function* clonedFunc, BasicBlock& clonedBB, uintptr_t &dest) {
    //create clone of module/function then analyze it.

   

    auto file_base = file_base_g;
    auto data = data_g;

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



    // create a pass that acatually works to promote memory to register
    // basically search for loads, if we stored a value to that load replace that value
    // problem 1:
    // multiple branches
    // we should fix control flow, then if we get the condition, since its SSA we can use the condition for branches and we create a select.
    //

    ROP_info result = ROP_return;
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(clonedBB.getTerminator());

    IRBuilder<> builder(&clonedBB);
    Value* rspvalue = GetRegisterValue(clonedBB.getContext(), builder, ZYDIS_REGISTER_RSP);
        // Check if the integer operand is a constant integer
    if (llvm::ConstantInt* constInt = llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
        int64_t rspval = constInt->getSExtValue();
        cout << "rspval = " << rspval << "\n";
        result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
        if (result == REAL_return) {
            return result;
       }
    }


    FPM.get()->doInitialization();
    FPM.get()->run(*clonedFunc);
    FPM.get()->doFinalization();
    //clonedFunc->print(outs());

    // Assuming you want to check the return value of the ReturnInst
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
JMP_info isJOP(Function* clonedFunc, BasicBlock& clonedBB, uintptr_t& dest) {
    //create clone of module/function then analyze it.



    auto file_base = file_base_g;
    auto data = data_g;

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

    // create a pass that acatually works to promote memory to register
    // basically search for loads, if we stored a value to that load replace that value
    // problem 1:
    // multiple branches
    // we should fix control flow, then if we get the condition, since its SSA we can use the condition for branches and we create a select.
    //

    FPM.get()->doInitialization();
    FPM.get()->run(*clonedFunc);
    FPM.get()->doFinalization();
    JMP_info result = REAL_jmp;
    //clonedFunc->print(outs());
    llvm::ReturnInst* returnInst = dyn_cast<llvm::ReturnInst>(clonedBB.getTerminator());

    // Assuming you want to check the return value of the ReturnInst
    if (returnInst->getReturnValue() != nullptr) {
        // Check if the return value is a constant integer
        if (llvm::ConstantInt* constInt = dyn_cast<llvm::ConstantInt>(returnInst->getReturnValue())) {
            dest = constInt->getZExtValue();
            result = JOP_jmp;
        }
    }



    return result;
}