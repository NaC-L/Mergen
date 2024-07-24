#include "CustomPasses.hpp"
#include "OperandUtils.h"
#include "includes.h"
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
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
          if (visited.find(userInst) == visited.end()) { // it can try to insert
                                                         // max 3 times here
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
  passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager,
                                   cGSCCAnalysisManager, moduleAnalysisManager);

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
    modulePassManager.addPass(PromotePseudoStackPass());

    modulePassManager.run(*module, moduleAnalysisManager);

    size_t afterSize = module->getInstructionCount();

    if (beforeSize != afterSize) {
      changed = true;
    }

  } while (changed);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(OptimizationLevel::O3);

  modulePassManager.addPass(ResizeAllocatedStackPass());
  modulePassManager.addPass(PromotePseudoMemory());

  modulePassManager.run(*module, moduleAnalysisManager);
}

llvm::ValueToValueMapTy* flipVMap(const ValueToValueMapTy& VMap) {

  ValueToValueMapTy* RevMap = new llvm::ValueToValueMapTy;
  for (const auto& pair : VMap) {
    (*RevMap)[pair.second] = const_cast<Value*>(pair.first);
  }
  return RevMap;
}

PATH_info solvePath(Function* function, uint64_t& dest, Value* simplifyValue) {

  PATH_info result = PATH_unsolved;
  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplifyValue)) {
    dest = constInt->getZExtValue();
    result = PATH_solved;
    return result;
  }

  if (PATH_info solved = getConstraintVal(function, simplifyValue, dest)) {
    if (solved == PATH_solved) {
      outs() << "Solved the constraint and moving to next path\n";
      outs().flush();
      return solved;
    }
  }

  return result;
}