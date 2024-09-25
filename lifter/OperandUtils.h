#pragma once
#include "includes.h"

Value* simplifyValue(Value* v, const DataLayout& DL);

Value* getMemory();

ReverseRegisterMap flipRegisterMap();

Value* ConvertIntToPTR(IRBuilder<>& builder, Value* effectiveAddress);

bool comesBefore(Instruction* a, Instruction* b, DominatorTree& DT);