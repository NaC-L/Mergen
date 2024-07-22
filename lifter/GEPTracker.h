#ifndef GEPTracker_H
#define GEPTracker_H

#include "includes.h"

enum Assumption { Real, Assumed }; // add None

namespace BinaryOperations {

  const char* getName(uint64_t offset);

  void initBases(void* file_base, ZyanU8* data);

  void getBases(void** file_base, ZyanU8** data);

  bool readMemory(uint64_t addr, unsigned byteSize, APInt& value);

  bool isWrittenTo(uint64_t addr);

}; // namespace BinaryOperations

namespace GEPStoreTracker {

  void initDomTree(Function& F);

  DominatorTree* getDomTree();

  void updateDomTree(Function& F);

  void updateMemoryOp(StoreInst* inst);

  void markMemPaged(uint64_t start, uint64_t end);

  bool isMemPaged(uint64_t address);

  void insertMemoryOp(StoreInst* inst);

  void loadMemoryOp(LoadInst* inst);

  Value* solveLoad(LoadInst* inst, bool buildTime = 1);

}; // namespace GEPStoreTracker

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/
#endif