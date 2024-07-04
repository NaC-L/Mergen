#pragma once
#include "includes.h"

Value* createSelectFolder(IRBuilder<>& builder, Value* C, Value* True,
                          Value* False, const Twine& Name = "");

Value* createAddFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name = "");

Value* createSubFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name = "");

Value* createOrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                      const Twine& Name = "");

Value* createXorFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name = "");

Value* createICMPFolder(IRBuilder<>& builder, CmpInst::Predicate P, Value* LHS,
                        Value* RHS, const Twine& Name = "");

Value* createAndFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name = "");

Value* createTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                         const Twine& Name = "");

Value* createZExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                        const Twine& Name = "");

Value* createZExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                               const Twine& Name = "");

Value* createSExtFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                        const Twine& Name = "");

Value* createSExtOrTruncFolder(IRBuilder<>& builder, Value* V, Type* DestTy,
                               const Twine& Name = "");

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                        const Twine& Name = "");

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, uint64_t RHS,
                        const Twine& Name = "");

Value* createLShrFolder(IRBuilder<>& builder, Value* LHS, APInt RHS,
                        const Twine& Name = "");

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, Value* RHS,
                       const Twine& Name = "");

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, uint64_t RHS,
                       const Twine& Name = "");

Value* createShlFolder(IRBuilder<>& builder, Value* LHS, APInt RHS,
                       const Twine& Name = "");

Value* GetRegisterValue(IRBuilder<>& builder, int key);

void SetRegisterValue(IRBuilder<>& builder, int key, Value* value);

void SetRegisterValue(int key, Value* value);

RegisterMap InitRegisters(IRBuilder<>& builder, Function* function,
                          ZyanU64 rip);

Value* ConvertIntToPTR(IRBuilder<>& builder, Value* effectiveAddress);

Value* GetEffectiveAddress(IRBuilder<>& builder, ZydisDecodedOperand& op,
                           int possiblesize);

IntegerType* getIntSize(int size, LLVMContext& context);

Value* GetOperandValue(IRBuilder<>& builder, ZydisDecodedOperand& op,
                       int possiblesize, string address = "");

Value* SetOperandValue(IRBuilder<>& builder, ZydisDecodedOperand& op,
                       Value* value, string address = "");

void pushFlags(IRBuilder<>& builder, vector<Value*> value, string address = "");

RegisterMap getRegisters();

void setRegisters(RegisterMap newRegisterList);

Value* setFlag(IRBuilder<>& builder, Flag flag, Value* newValue);

Value* getFlag(IRBuilder<>& builder, Flag flag);

Value* getMemoryFromValue(IRBuilder<>& builder, Value* value);

vector<Value*> GetRFLAGS(IRBuilder<>& builder);

Value* getMemory();

KnownBits analyzeValueKnownBits(Value* value, const DataLayout& DL);

Value* simplifyValueLater(Value* v, const DataLayout& DL);

ReverseRegisterMap flipRegisterMap();

Value* popStack(IRBuilder<>& builder);

bool comesBefore(Instruction* a, Instruction* b, DominatorTree& DT);