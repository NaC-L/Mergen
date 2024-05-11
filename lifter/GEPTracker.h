#pragma once
#include "includes.h"
#include "OperandUtils.h"

#ifndef GEPTracker_H
#define GEPTracker_H
using memoryValue = Value*;
using idxValue = Value*;
using ptrValue = Value*;

using memoryInfo = tuple<ptrValue, idxValue, memoryValue, bool>;


namespace BinaryOperations {

	const char* getName(unsigned long long offset);

	void initBases(void* file_base, ZyanU8* data);

	void getBases(void** file_base, ZyanU8** data);

	bool readMemory(uintptr_t addr, unsigned byteSize, APInt& value);

};

namespace GEPStoreTracker {

	void initDomTree(Function& F);

	void updateDomTree(Function& F);

	Value* solveLoad(LoadInst* inst, bool buildTime = 1);

	DominatorTree* getDomTree();

	void insertMemoryOp(Instruction* inst);

	void insertInfo(ptrValue pv, idxValue av, memoryValue mv, bool isStore);

	// we use this as a loadValue
	memoryValue getValueAt(IRBuilder<>& builder, ptrValue pv, idxValue iv, unsigned int byteCount);


};
#endif