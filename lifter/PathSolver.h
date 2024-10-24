#pragma once
#include "includes.h"
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

void final_optpass(Function* clonedFuncx);

void final_optpass(llvm::Function* clonedFuncx);

PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);