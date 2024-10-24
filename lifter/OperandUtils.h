#pragma once
#include "includes.h"
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>


llvm::Value* simplifyValue(llvm::Value* v, const llvm::DataLayout& DL);

llvm::Value* getMemory();


bool comesBefore(llvm::Instruction* a, llvm::Instruction* b,
                 llvm::DominatorTree& DT);
