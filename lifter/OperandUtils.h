#pragma once
#include "includes.h"


Value* createSelectFolder(IRBuilder<>& builder, Value* C, Value* True, Value* False, const Twine& Name = "");
Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createICMPFolder(IRBuilder<>& builder, CmpInst::Predicate P, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");

Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "");

Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "");
Value* createZExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "");
Value* createSExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "");
Value* createSExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy, const Twine& Name = "");

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");
Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, uintptr_t RHS, const Twine& Name = "");
Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, APInt RHS, const Twine& Name = "");
Value* createShlFolder(IRBuilder<>& builder, Value* LHS, Value* RHS, const Twine& Name = "");
Value* createShlFolder(IRBuilder<>& builder, Value* LHS, uintptr_t RHS, const Twine& Name = "");
Value* createShlFolder(IRBuilder<>& builder, Value* LHS, APInt RHS, const Twine& Name = "");
Value* GetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key);
void SetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key, Value* value);
unordered_map<int, Value*> InitRegisters(LLVMContext& context, IRBuilder<>& builder,Function* function, ZyanU64 rip);

Value* GetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize, string address = "");
Value* GetEffectiveAddress(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize);
IntegerType* getIntSize(int size, LLVMContext& context);

Value* SetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, Value* value, string address = "");

unordered_map<int, Value*> getRegisterList();

void setRegisterList(unordered_map<int, Value*> newRegisterList);

Value* setFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue);
Value* getFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag);


void initBases2(void* file_base, ZyanU8* data);

Value* getMemoryFromValue(LLVMContext& context, IRBuilder<>& builder, Value* value);

void pushFlags(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, vector<Value*> value, string address = "");
vector<Value*> GetRFLAGS(LLVMContext& context, IRBuilder<>& builder);