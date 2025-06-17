#ifndef GEPTracker_H
#define GEPTracker_H

#include "MemoryPolicy.hpp"
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/IR/Value.h>

using namespace llvm;

enum Assumption { Real, Assumed }; // add None

enum isPaged { MEMORY_PAGED, MEMORY_MIGHT_BE_PAGED, MEMORY_NOT_PAGED };

struct APIntComparator {
  bool operator()(const llvm::APInt& lhs, const llvm::APInt& rhs) const {
    return lhs.ult(rhs); // unsigned less-than comparison
  }
};

class ValueByteReference {
public:
  // Instruction* storeInst;
  llvm::Value* value;
  uint8_t byteOffset;
  // ValueByteReference() : storeInst(nullptr), value(nullptr), byteOffset(0) {}
  ValueByteReference() : value(nullptr), byteOffset(0) {}

  /*
    ValueByteReference(Instruction* inst, Value* val, short offset)
        : storeInst(inst), value(val), byteOffset(offset) {}
        */

  ValueByteReference(llvm::Value* val, short offset)
      : value(val), byteOffset(offset) {}
};

class ValueByteReferenceRange {
public:
  union {
    ValueByteReference ref;
    uint64_t memoryAddress;
  };

  uint8_t start;
  uint8_t end;

  bool isRef;
  ValueByteReferenceRange(ValueByteReference vref, uint8_t startv, uint8_t endv)
      : ref(vref), start(startv), end(endv), isRef(true) {}

  // Constructor for ValueByteReferenceRange using memoryAddress
  ValueByteReferenceRange(uint64_t addr, uint8_t startv, uint8_t endv)
      : memoryAddress(addr), start(startv), end(endv), isRef(false) {}
};

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/

#endif