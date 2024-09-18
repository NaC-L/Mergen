#ifndef GEPTracker_H
#define GEPTracker_H

#include "includes.h"

enum Assumption { Real, Assumed }; // add None

enum isPaged { MEMORY_PAGED, MEMORY_MIGHT_BE_PAGED, MEMORY_NOT_PAGED };

struct APIntComparator {
  bool operator()(const APInt& lhs, const APInt& rhs) const {
    return lhs.ult(rhs); // unsigned less-than comparison
  }
};

class ValueByteReference {
public:
  Instruction* storeInst;
  Value* value;
  unsigned short byteOffset;
  ValueByteReference() : storeInst(nullptr), value(nullptr), byteOffset(0) {}

  ValueByteReference(Instruction* inst, Value* val, short offset)
      : storeInst(inst), value(val), byteOffset(offset) {}
};

class ValueByteReferenceRange {
public:
  union {
    ValueByteReference ref;
    uint64_t memoryAddress;
  };

  // size info, we can make this smaller because they can only be 0-8 range
  // (maybe higher for avx)
  uint8_t start;
  uint8_t end;

  bool isRef;
  ValueByteReferenceRange(ValueByteReference vref, uint8_t startv, uint8_t endv)
      : ref(vref), start(startv), end(endv), isRef(true) {}

  // Constructor for ValueByteReferenceRange using memoryAddress
  ValueByteReferenceRange(uint64_t addr, uint8_t startv, uint8_t endv)
      : memoryAddress(addr), start(startv), end(endv), isRef(false) {}
};

namespace BinaryOperations {

  const char* getName(const uint64_t offset);

  void initBases(void* file_base, ZyanU8* data); // ?

  void getBases(void** file_base, ZyanU8** data);

  bool isImport(const uint64_t addr);

  bool readMemory(const uint64_t addr, unsigned byteSize, APInt& value);

  bool isWrittenTo(const uint64_t addr);

}; // namespace BinaryOperations

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/
#endif