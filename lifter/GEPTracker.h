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

    void initBases(void* file_base, ZyanU8* data);
    
    void getBases(void* file_base, ZyanU8* data);

    APInt* readMemory(uintptr_t addr, unsigned byteSize);

};

namespace GEPStoreTracker {

    Value* solveLoad(LoadInst* inst);

    void insertMemoryOp(Instruction* inst);

    void insertInfo(ptrValue pv, idxValue av, memoryValue mv, bool isStore);

    // we use this as a loadValue
    memoryValue getValueAt(IRBuilder<>& builder, ptrValue pv, idxValue iv, unsigned int byteCount);


};
#endif