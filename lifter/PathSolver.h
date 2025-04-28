#pragma once
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
};

PATH_info getConstraintVal(llvm::Function* function, llvm::Value* constraint,
                           uint64_t& dest);

void final_optpass(llvm::Function* clonedFuncx, llvm::Value* mem,
                   uint8_t* filebase);

PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);