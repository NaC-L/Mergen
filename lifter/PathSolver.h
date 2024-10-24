#pragma once
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
};

void final_optpass(llvm::Function* clonedFuncx);

PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);