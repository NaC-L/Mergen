#pragma once
#include "MemoryPolicy.hpp"
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
  PATH_multi_solved = 2,  // >2 targets resolved via SwitchInst
};

// Cancellation-aware path-target simplifier. Walks the def-chain rooted at
// `V`, expanding add/sub/neg into a canonical sum-of-terms, combining like
// terms by SSA identity, and rebuilding a clean expression at the builder's
// current insert point when the canonical form is strictly simpler. Returns
// the simplified Value (which may equal V when no win is available).
llvm::Value* deepSimplifyValue(
    llvm::Value* V,
    llvm::IRBuilder<llvm::InstSimplifyFolder>* builder,
    const llvm::DataLayout& DL);

PATH_info getConstraintVal(llvm::Function* function, llvm::Value* constraint,
                           uint64_t& dest);


PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);