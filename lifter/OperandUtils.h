#pragma once
#include "includes.h"

namespace GetSimplifyQuery {
    
  extern Function* fnc;
  void RegisterBranch(BranchInst* BI);

  SimplifyQuery createSimplifyQuery(Function* fnc);

} // namespace GetSimplifyQuery

Value* simplifyValue(Value* v, const DataLayout& DL);

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

Value* getMemory();

KnownBits analyzeValueKnownBits(Value* value, Instruction* ctxI);

ReverseRegisterMap flipRegisterMap();

Value* ConvertIntToPTR(IRBuilder<>& builder, Value* effectiveAddress);

bool comesBefore(Instruction* a, Instruction* b, DominatorTree& DT);