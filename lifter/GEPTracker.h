#ifndef GEPTracker_H
#define GEPTracker_H

#include "includes.h"
namespace BinaryOperations {

    const char* getName(uint64_t offset);

    void initBases(void* file_base, ZyanU8* data);

    void getBases(void** file_base, ZyanU8** data);

    bool readMemory(uint64_t addr, unsigned byteSize, APInt& value);

    bool isWrittenTo(uint64_t addr);

}; // namespace BinaryOperations

namespace GEPStoreTracker {

    void initDomTree(Function& F);

    void updateDomTree(Function& F);

    Value* solveLoad(LoadInst* inst, bool buildTime = 1);

    DominatorTree* getDomTree();

    void insertMemoryOp(StoreInst* inst);

    void updateMemoryOp(StoreInst* inst);

}; // namespace GEPStoreTracker

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/
#endif