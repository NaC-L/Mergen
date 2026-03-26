#pragma once
#include "MemoryPolicy.hpp"
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
  PATH_multi_solved = 2,  // >2 targets resolved via SwitchInst
};

PATH_info getConstraintVal(llvm::Function* function, llvm::Value* constraint,
                           uint64_t& dest);


PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);