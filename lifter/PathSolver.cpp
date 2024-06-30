#include "CustomPasses.hpp"
#include "OperandUtils.h"
#include "includes.h"
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>

void* file_base_g;
ZyanU8* data_g;

struct InstructionDependencyOrder {
    bool operator()(Instruction* const& a, Instruction* const& b) const {

        Function* F = a->getFunction();
        GEPStoreTracker::updateDomTree(*F);
        DominatorTree* DT = GEPStoreTracker::getDomTree();

        return (comesBefore(b, a, *DT));
    }
};

void replaceAllUsesWithandReplaceRMap(Value* v, Value* nv,
                                      ReverseRegisterMap rVMap) {

    // if two values are same, we go in a infinite loop
    if (v == nv)
        return;

    auto registerV = rVMap[v];

    if (registerV) {
        if (isa<Instruction>(v)) {
            // auto registerI = cast<Instruction>(v);
            SetRegisterValue(registerV, v);
        }
    }

    v->replaceAllUsesWith(nv);

    // redundant?
    v = nv;

    // dont ask me this i dont know

    // users start from latest user
    std::vector<User*> users;
    for (auto& use : v->uses()) {
        users.push_back(use.getUser());
    }

    // iterate over the users in reverse order
    for (auto it = users.rbegin(); it != users.rend(); ++it) {
        User* user = *it;
        if (auto GEPuser = dyn_cast<GetElementPtrInst>(user)) {
            for (auto StoreUser : GEPuser->users()) {
                if (auto SI = dyn_cast<StoreInst>(StoreUser)) {
                    GEPStoreTracker::updateMemoryOp(SI);
                }
            }
        }
    }
}

// simplify Users with BFS
// because =>
// x = add a, b
// if we go simplify a then simplify x, then simplify b, we might miss
// simplifying x if we go simplify a, then simplify b, then simplify x we will
// not miss
//
// also refactor this
void simplifyUsers(Value* newValue, DataLayout& DL,
                   ReverseRegisterMap flippedRegisterMap) {
    unordered_set<Value*> visited;
    std::priority_queue<Instruction*, std::vector<Instruction*>,
                        InstructionDependencyOrder>
        toSimplify;
    for (User* user : newValue->users()) {
        if (Instruction* userInst = dyn_cast<Instruction>(user)) {
            toSimplify.push(userInst);
        }
    }

    while (!toSimplify.empty()) {
        auto simplifyUser = toSimplify.top();
        toSimplify.pop();
        auto nsv = simplifyValueLater(simplifyUser, DL);

        visited.insert(simplifyUser);
        printvalue(simplifyUser) printvalue(nsv);

        if (isa<GetElementPtrInst>(simplifyUser)) {
            for (User* user : simplifyUser->users()) {
                if (Instruction* userInst = dyn_cast<Instruction>(user)) {
                    if (visited.find(userInst) ==
                        visited.end()) { // it can try to insert max 3 times
                                         // here
                        toSimplify.push(userInst);
                        visited.insert(userInst);
                    }
                }
            }
        }

        // if values are identical, we will get into a loop and cant simplify
        if (simplifyUser == nsv) {
            continue;
        }
        // if can simplify, continue?

        for (User* user : simplifyUser->users()) {
            if (Instruction* userInst = dyn_cast<Instruction>(user)) {
                if (visited.find(userInst) == visited.end()) {
                    toSimplify.push(userInst);
                    visited.erase(userInst);
                }
            }
        }

        replaceAllUsesWithandReplaceRMap(simplifyUser, nsv, flippedRegisterMap);
    }
}
PATH_info getConstraintVal(llvm::Function* function, Value* constraint,
                           uint64_t& dest) {
    PATH_info result = PATH_unsolved;
    printvalue(constraint);
    auto simplified_constraint = simplifyValueLater(
        constraint,
        function->getParent()->getDataLayout()); // this is such a hack
    printvalue(simplified_constraint);

    if (llvm::ConstantInt* constInt =
            dyn_cast<llvm::ConstantInt>(simplified_constraint)) {
        printvalue(constInt) dest = constInt->getZExtValue();
        result = PATH_solved;
        return result;
    }

    return result;
}

// https://github.com/llvm/llvm-project/blob/30f6eafaa978b4e0211368976fe60f15fa9f0067/llvm/unittests/Support/KnownBitsTest.h#L38
/* ex:
KnownBits Known1;
vector<APInt> possiblevalues;
ForeachNumInKnownBits(Known1, [&](APInt Value1) {
possiblevalues.push_back(Value1); });
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

std::vector<llvm::APInt> getPossibleValues(const llvm::KnownBits& known,
                                           unsigned max_unknown) {
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
    passBuilder.crossRegisterProxies(
        loopAnalysisManager, functionAnalysisManager, cGSCCAnalysisManager,
        moduleAnalysisManager);

    llvm::ModulePassManager modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O0);

    llvm::Module* module = clonedFuncx->getParent();

    bool changed;
    do {
        changed = false;

        size_t beforeSize = module->getInstructionCount();

        modulePassManager =
            passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
        modulePassManager.addPass(GEPLoadPass());
        modulePassManager.addPass(ReplaceTruncWithLoadPass());
        modulePassManager.addPass(RemovePseudoStackPass());

        modulePassManager.run(*module, moduleAnalysisManager);

        size_t afterSize = module->getInstructionCount();

        if (beforeSize != afterSize) {
            changed = true;
        }

    } while (changed);

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);
    modulePassManager.addPass(RemovePseudoMemory());

    modulePassManager.run(*module, moduleAnalysisManager);
}

llvm::ValueToValueMapTy* flipVMap(const ValueToValueMapTy& VMap) {

    ValueToValueMapTy* RevMap = new llvm::ValueToValueMapTy;
    for (const auto& pair : VMap) {
        (*RevMap)[pair.second] = const_cast<Value*>(pair.first);
    }
    return RevMap;
}

PATH_info solvePath(Function* function, uintptr_t& dest, Value* simplifyValue) {

    PATH_info result = PATH_unsolved;
    if (llvm::ConstantInt* constInt =
            dyn_cast<llvm::ConstantInt>(simplifyValue)) {
        dest = constInt->getZExtValue();
        result = PATH_solved;
        return result;
    }

    auto flippedRegisterMap = flipRegisterMap();

    while (dest == 0) {

        if (PATH_info solved =
                getConstraintVal(function, simplifyValue, dest)) {
            if (solved == PATH_solved) {
                outs() << "Solved the constraint and moving to next path\n";
                outs().flush();
                return solved;
            }
        }

        deque<llvm::Instruction*> worklist;
        std::vector<llvm::Instruction*> visited_used;
        std::unordered_set<llvm::Instruction*> visited_used_set;

        // Start with the return instruction
        worklist.push_front(cast<Instruction>(simplifyValue));

        while (!worklist.empty()) {
            llvm::Instruction* inst = worklist.front();
            worklist.pop_front();
            visited_used.emplace_back(inst);

            for (unsigned i = 0, e = inst->getNumOperands(); i != e; ++i) {
                llvm::Value* operand = inst->getOperand(i);
                if (llvm::Instruction* opInst =
                        llvm::dyn_cast<llvm::Instruction>(operand)) {
                    printvalue(opInst);
                    if (visited_used_set.insert(opInst).second) {
                        worklist.push_back(opInst);
                    }
                }
            }
        }

        Value* value_with_least_possible_values = nullptr;
        unsigned int least_possible_value_value = INT_MAX;
        KnownBits bitsof_least_possible_value(64);

        DataLayout DL(function->getParent());

        // find the VWLPV(value with least possible values) that builds up to
        // the returnValue
        for (auto I : visited_used) {
            KnownBits KnownVal = analyzeValueKnownBits(I, DL);

            unsigned int possible_values =
                llvm::popcount(~(KnownVal.Zero | KnownVal.One).getZExtValue()) *
                2;
            possible_values = min(possible_values, KnownVal.getBitWidth() * 2);
            printvalue(I);
            printvalue2(possible_values);
            printvalue2(KnownVal);
            if (!KnownVal.isConstant() && !KnownVal.hasConflict() &&
                possible_values < least_possible_value_value &&
                possible_values > 0) {
                least_possible_value_value = possible_values;
                value_with_least_possible_values = cast<Value>(I);
                bitsof_least_possible_value = KnownVal;
            }

            // if constant, simplify later users?
            // simplify it aswell
            // if (KnownVal.isConstant() && !KnownVal.hasConflict()) {
            printvalue(I) auto nsv = simplifyValueLater(I, DL);
            printvalue(nsv);

            replaceAllUsesWithandReplaceRMap(I, nsv, flippedRegisterMap);
            simplifyUsers(nsv, DL, flippedRegisterMap);
            //}
        }

        if (PATH_info solved =
                getConstraintVal(function, simplifyValue, dest)) {
            if (solved == PATH_solved) {
                return solved;
            }
        }

        //  cout << "Total user: " << total_user << "\n";
        if (least_possible_value_value == 0)
            throw("something went wrong");

        outs() << " value_with_least_possible_values: ";
        value_with_least_possible_values->print(outs());
        outs() << "\n";
        outs().flush();
        outs() << " bitsof_least_possible_value : "
               << bitsof_least_possible_value << "\n";
        outs().flush();
        outs() << " possible values: " << least_possible_value_value << " : \n";

        // print an optimized version?
        std::string Filename = "output_trysolve.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        function->getParent()->print(OS, nullptr);

        auto possible_values = getPossibleValues(
            bitsof_least_possible_value, least_possible_value_value - 1);
        auto original_value = value_with_least_possible_values;

        unsigned max_possible_values = possible_values.size();
        for (unsigned i = 0; i < max_possible_values; i++) {
            outs() << i << "-) v : " << possible_values[i] << "\n";
        }

        cout << "\nWhich option do you select? ";
        // TODO:
        // store current state
        // make it identify assumptions
        // create a new lifter state
        // should look like
        // Lifter(function, basicblock, assumptions, registermap, memorymap)
        //
        unsigned long long option = 0;
        timer::suspendTimer();
        cin >> option;
        timer::resumeTimer();
        auto newValue =
            ConstantInt::get(value_with_least_possible_values->getType(),
                             possible_values[option]);

        // replace original value with the value we selected
        replaceAllUsesWithandReplaceRMap(original_value, newValue,
                                         flippedRegisterMap);
        // original_value->replaceAllUsesWith(newValue);

        // simplify later usages
        simplifyUsers(newValue, DL, flippedRegisterMap);

#ifdef _DEBUG
        std::string Filename3 = "output_trysolve2.ll";
        std::error_code EC3;
        raw_fd_ostream OS3(Filename3, EC3);
        function->print(OS3, nullptr);
        // receive input, replace the value with received input
        // re-run program
#endif
    }
    return result;
}