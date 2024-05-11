#pragma once
#include "includes.h"

void test_optxd(Function* clonedFuncx);

void final_optpass(Function* clonedFuncx);

opaque_info isOpaque(Function* function);

ROP_info isROP(Function* function, BasicBlock& clonedBB, uintptr_t& dest);

JMP_info isJOP(Function* function, uintptr_t& dest);

PATH_info solvePath(Function* function, uintptr_t& dest, string debug_filename);