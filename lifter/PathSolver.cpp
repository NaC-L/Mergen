
#include "PathSolver.h"
#include "CustomPasses.hpp"
#include "utils.h"
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

// simplify Users with BFS
// because =>
// x = add a, b
// if we go simplify a then simplify x, then simplify b, we might miss
// simplifying x if we go simplify a, then simplify b, then simplify x we will
// not miss
//
// also refactor this

PATH_info getConstraintVal(llvm::Function* function, Value* constraint,
                           uint64_t& dest) {
  PATH_info result = PATH_unsolved;
  printvalue(constraint);
  /*
   auto simplified_constraint = simplifyValue(
       constraint,
       function->getParent()->getDataLayout()); // this is such a hack
       //
  printvalue(simplified_constraint);

  if (llvm::ConstantInt* constInt =
          dyn_cast<llvm::ConstantInt>(simplified_constraint)) {
    printvalue(constInt) dest = constInt->getZExtValue();
    result = PATH_solved;
    return result;
  }
  */

  return result;
}
