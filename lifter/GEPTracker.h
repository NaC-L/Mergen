#ifndef GEPTracker_H
#define GEPTracker_H

#include <Zycore/Types.h>
#include <llvm/ADT/APInt.h>
#include <llvm/IR/Value.h>

using namespace llvm;

enum Assumption { Real, Assumed }; // add None

enum arch_mode { X86 = 0, X64 = 1 };

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

namespace BinaryOperations {
  extern bool concretize_unsafe_reads;
  const char* getName(const uint64_t offset);

  int getBitness();

  void initBases(ZyanU8* data, arch_mode is64); // ?

  void getBases(ZyanU8** data);

  bool isImport(uint64_t addr);

  bool readMemory(const uint64_t addr, unsigned byteSize, llvm::APInt& value);

  bool isWrittenTo(const uint64_t addr);

  uint64_t RvaToFileOffset(const void* ntHeadersBase, uint32_t rva);

  uint64_t address_to_mapped_address(uint64_t rva);

  uint64_t fileOffsetToRVA(uint64_t fileAddress);

}; // namespace BinaryOperations

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/
#endif