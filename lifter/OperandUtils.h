#pragma once
#include "includes.h"
Value* GetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key);

void SetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key, Value* value);
unordered_map<int, Value*> InitRegisters(LLVMContext& context, IRBuilder<>& builder,Function* function, ZyanU64 rip);

Value* GetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize);
Value* GetEffectiveAddress(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize);
IntegerType* getIntSize(int size, LLVMContext& context);

Value* SetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, Value* value);

unordered_map<int, Value*> getRegisterList();

void setRegisterList(unordered_map<int, Value*> newRegisterList);

Value* setFlag(LLVMContext& context, IRBuilder<>& builder, Value* rflag_var, Flag flag, FlagOperation operation, Value* newValue = nullptr);


Value* getFlag(LLVMContext& context, IRBuilder<>& builder, Value* rflag_var, Flag flag);


void initBases2(LPVOID file_base, ZyanU8* data);
