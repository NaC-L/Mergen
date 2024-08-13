#ifndef GEPTracker_H
#define GEPTracker_H

#include "includes.h"

enum Assumption { Real, Assumed }; // add None

class ValueByteReference {
public:
  Instruction* storeInst;
  Value* value;
  unsigned short byteOffset;

  ValueByteReference(Instruction* inst, Value* val, short offset)
      : storeInst(inst), value(val), byteOffset(offset) {}
};

class ValueByteReferenceRange {
public:
  union val {
    ValueByteReference* ref;
    uint64_t memoryAddress;

    val(ValueByteReference* vref) : ref(vref) {}
    val(uint64_t addr) : memoryAddress(addr) {}

  } valinfo;

  // size info, we can make this smaller because they can only be 0-8 range
  // (maybe higher for avx)
  uint8_t start;
  uint8_t end;

  bool isRef;
  ValueByteReferenceRange(ValueByteReference* vref, uint8_t startv,
                          uint8_t endv)
      : valinfo(vref), start(startv), end(endv), isRef(true) {}

  // Constructor for ValueByteReferenceRange using memoryAddress
  ValueByteReferenceRange(uint64_t addr, uint8_t startv, uint8_t endv)
      : valinfo(addr), start(startv), end(endv), isRef(false) {}
};

class lifterMemoryBuffer {
public:
  DenseMap<uint64_t, ValueByteReference*> buffer;
  void addValueReference(Instruction* inst, Value* value, uint64_t address);
  Value* retrieveCombinedValue(IRBuilder<>& builder, uint64_t startAddress,
                               uint64_t byteCount, Value* orgLoad);
  void updateValueReference(Instruction* inst, Value* value, uint64_t address);

private:
  Value* extractBytes(IRBuilder<>& builder, Value* value, uint64_t startOffset,
                      uint64_t endOffset);
};

namespace BinaryOperations {

  const char* getName(uint64_t offset);

  void initBases(void* file_base, ZyanU8* data);

  void getBases(void** file_base, ZyanU8** data);

  bool isImport(uint64_t addr);

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

  Value* solveLoad(LoadInst* inst);

}; // namespace GEPStoreTracker

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/
#endif