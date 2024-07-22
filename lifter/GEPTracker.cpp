#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Support/ErrorHandling.h>

namespace BinaryOperations {
  void* file_base_g;
  ZyanU8* data_g;

  void initBases(void* file_base, ZyanU8* data) {
    file_base_g = file_base;
    data_g = data;
  }

  void getBases(void** file_base, ZyanU8** data) {
    *file_base = file_base_g;
    *data = data_g;
  }

  const char* getName(uint64_t offset) {
    auto dosHeader = (win::dos_header_t*)file_base_g;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)file_base_g + dosHeader->e_lfanew);
    auto rvaOffset = FileHelper::RvaToFileOffset(ntHeaders, offset);
    return (const char*)file_base_g + rvaOffset;
  }

  unordered_set<uint64_t> MemWrites;

  bool isWrittenTo(uint64_t addr) {
    return MemWrites.find(addr) != MemWrites.end();
  }
  void WriteTo(uint64_t addr) { MemWrites.insert(addr); }

  // sections
  bool readMemory(uint64_t addr, unsigned byteSize, APInt& value) {

    uint64_t mappedAddr =
        FileHelper::address_to_mapped_address(file_base_g, addr);
    uint64_t tempValue;

    if (mappedAddr > 0) {
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(data_g + mappedAddr), byteSize);

      APInt readValue(byteSize * 8, tempValue);
      value = readValue;
      return 1;
    }

    return 0;
  }

  // TODO
  // 1- if writes into execute section, flag that address, if we execute that
  // address then do fancy stuff to figure out what we wrote so we know what
  // we will be executing
  void writeMemory();

}; // namespace BinaryOperations

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
  bool isRef;

  // size info, we can make this smaller because they can only be 0-8 range
  // (maybe higher for avx)
  uint8_t start;
  uint8_t end;

  ValueByteReferenceRange(ValueByteReference* vref, uint8_t startv,
                          uint8_t endv)
      : valinfo(vref), start(startv), end(endv), isRef(true) {}

  // Constructor for ValueByteReferenceRange using memoryAddress
  ValueByteReferenceRange(uint64_t addr, uint8_t startv, uint8_t endv)
      : valinfo(addr), start(startv), end(endv), isRef(false) {}
};

class lifterMemoryBuffer {
public:
  std::unordered_map<uint64_t, ValueByteReference*> buffer;

  void addValueReference(Instruction* inst, Value* value, uint64_t address) {
    unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
    for (unsigned i = 0; i < valueSizeInBytes; i++) {

      delete buffer[address + i];
      BinaryOperations::WriteTo(address + i);
      printvalue2(address + i);
      buffer[address + i] = new ValueByteReference(inst, value, i);
      printvalue(value);
      printvalue2((uint64_t)address + i);
    }
  }

  void updateValueReference(Instruction* inst, Value* value, uint64_t address) {
    unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
    for (unsigned i = 0; i < valueSizeInBytes; i++) {
      auto existingValue = buffer[address + i];
      auto DT = GEPStoreTracker::getDomTree();

      if (comesBefore(inst, existingValue->storeInst, *DT)) {
        continue;
      }

      printvalue2(address + i);

      buffer[address + i] = new ValueByteReference(inst, value, i);

      printvalue(value);

      printvalue2((uint64_t)address + i);
    }
  }

  Value* retrieveCombinedValue(IRBuilder<>& builder, uint64_t startAddress,
                               uint64_t byteCount) {
    LLVMContext& context = builder.getContext();
    if (byteCount == 0) {
      return nullptr;
    }

    bool contiguous = true;

    vector<ValueByteReferenceRange> values; // we can just create an array here
    for (uint64_t i = 0; i < byteCount; ++i) {
      uint64_t currentAddress = startAddress + i;
      if (buffer[currentAddress] == nullptr ||
          buffer[currentAddress]->value != buffer[startAddress]->value ||
          buffer[currentAddress]->byteOffset != i) {
        contiguous = false; // non-contiguous value
      }

      // push if
      if (values.empty() ||                                 // empty or
          (buffer[currentAddress] && values.back().isRef && // ( its a reference
           (values.back().valinfo.ref->value !=
                buffer[currentAddress]
                    ->value || // and references are not same or
            values.back().valinfo.ref->byteOffset !=
                buffer[currentAddress]->byteOffset - values.back().end +
                    values.back().start)) //  reference offset is not directly
                                          //  next value )
      ) {

        if (buffer[currentAddress]) {
          values.push_back(
              ValueByteReferenceRange(buffer[currentAddress], i, i + 1));
        } else {
          values.push_back(ValueByteReferenceRange(currentAddress, i, i + 1));
        }
      } else {
        ++values.back().end;
      }
    }

    // if value is contiguous and value exists but we are trying to load a
    // truncated value
    // no need for this ?
    /*
    if (contiguous && buffer[startAddress] &&
        byteCount <=
            buffer[startAddress]->value->getType()->getIntegerBitWidth() / 8) {
      return builder.CreateTrunc(buffer[startAddress]->value,
                                 Type::getIntNTy(context, byteCount * 8)); // ?
    }
    */

    // when do we want to return nullptr and when do we want to return 0?
    // we almost always want to return a value
    Value* result =
        ConstantInt::get(Type::getIntNTy(context, byteCount * 8), 0);

    int m = 0;
    for (auto v : values) {
      Value* byteValue = nullptr;
      unsigned bytesize = v.end - v.start;

      APInt mem_value(1, 0);
      if (v.isRef && v.valinfo.ref != nullptr) {
        byteValue = extractBytes(builder, v.valinfo.ref->value,
                                 v.valinfo.ref->byteOffset,
                                 v.valinfo.ref->byteOffset + bytesize);
      } else if (!v.isRef &&
                 BinaryOperations::readMemory(v.valinfo.memoryAddress, bytesize,
                                              mem_value)) {
        byteValue = builder.getIntN(bytesize * 8, mem_value.getZExtValue());
      }
      if (byteValue) {
        printvalue(byteValue);

        Value* shiftedByteValue = createShlFolder(
            builder,
            createZExtFolder(builder, byteValue,
                             Type::getIntNTy(context, byteCount * 8)),
            APInt(byteCount * 8, m * 8));
        result = createOrFolder(builder, result, shiftedByteValue,
                                "extractbytesthing");
      }
      m += bytesize;
    }

    return result;
  }

private:
  Value* extractBytes(IRBuilder<>& builder, Value* value, uint64_t startOffset,
                      uint64_t endOffset) {
    LLVMContext& context = builder.getContext();

    if (!value) {
      return ConstantInt::get(
          Type::getIntNTy(context, (endOffset - startOffset) * 8), 0);
    }

    uint64_t byteCount = endOffset - startOffset;

    uint64_t shiftAmount = startOffset * 8;

    printvalue2(endOffset);

    printvalue2(startOffset);
    printvalue2(byteCount);
    printvalue2(shiftAmount);

    Value* shiftedValue = createLShrFolder(
        builder, value,
        APInt(value->getType()->getIntegerBitWidth(), shiftAmount),
        "extractbytes");
    printvalue(value);
    printvalue(shiftedValue);

    Value* truncatedValue = createTruncFolder(
        builder, shiftedValue, Type::getIntNTy(context, byteCount * 8));
    return truncatedValue;
  }
};

namespace SCCPSimplifier {
  std::unique_ptr<SCCPSolver> solver;
  uint64_t lastinstcount = 0;
  void init(Function* function) {
    if (function->getInstructionCount() == lastinstcount)
      return;
    lastinstcount = function->getInstructionCount();
    auto GetTLI = [](Function& F) -> const TargetLibraryInfo& {
      static TargetLibraryInfoImpl TLIImpl(
          Triple(F.getParent()->getTargetTriple()));
      static TargetLibraryInfo TLI(TLIImpl);
      return TLI;
    };

    solver = std::make_unique<SCCPSolver>(
        function->getParent()->getDataLayout(), GetTLI, function->getContext());
    solver->markBlockExecutable(&(function->front()));
    bool ResolvedUndefs = true;
    while (ResolvedUndefs) {
      solver->solve();
      ResolvedUndefs = solver->resolvedUndefsIn(*function);
    }
  }
  SCCPSolver* get() { return solver.get(); }

  void cleanup() { solver.reset(); }
} // namespace SCCPSimplifier

// do some cleanup
// rename it to MemoryTracker ?
namespace GEPStoreTracker {
  DominatorTree* DT;
  BasicBlock* lastBB = nullptr;

  // best to use whenever possible
  lifterMemoryBuffer VirtualStack;

  void initDomTree(Function& F) { DT = new DominatorTree(F); }
  DominatorTree* getDomTree() { return DT; }

  void updateDomTree(Function& F) {
    // doesnt make a much difference, but good to have
    auto getLastBB = &(F.back());
    if (getLastBB != lastBB)
      DT->recalculate(F);
    lastBB = getLastBB;
  }

  vector<Instruction*> memInfos;
  void updateMemoryOp(StoreInst* inst) {

    auto ptr = inst->getPointerOperand();
    if (!isa<GetElementPtrInst>(ptr))
      return;

    auto gepInst = cast<GetElementPtrInst>(ptr);
    auto gepPtr = gepInst->getPointerOperand();
    if (gepPtr != getMemory())
      return;

    auto gepOffset = gepInst->getOperand(1);
    if (!isa<ConstantInt>(gepOffset))
      return;

    auto gepOffsetCI = cast<ConstantInt>(gepOffset);

    VirtualStack.updateValueReference(inst, inst->getValueOperand(),
                                      gepOffsetCI->getZExtValue());
  }

  map<uint64_t, uint64_t> pageMap;

  void markMemPaged(uint64_t start, uint64_t end) {
    //
    pageMap[start] = end;
  }

  bool isMemPaged(uint64_t address) {
    // ideally we want to be able to do this with KnownBits aswell
    auto it = pageMap.upper_bound(address);
    if (it == pageMap.begin())
      return false;
    --it;
    return address >= it->first && address < it->second;
  }

  enum isPaged { MEMORY_PAGED, MEMORY_MIGHT_BE_PAGED, MEMORY_NOT_PAGED };

  isPaged isValuePaged(Value* address, const DataLayout& DL) {
    if (isa<ConstantInt>(address)) {
      return isMemPaged(cast<ConstantInt>(address)->getZExtValue())
                 ? MEMORY_PAGED
                 : MEMORY_NOT_PAGED;
    }
    auto KBofAddress = analyzeValueKnownBits(address, DL);

    for (const auto& page : pageMap) {
      uint64_t start = page.first;
      uint64_t end = page.second;
      // KBofAddress >= start && KBofAddress < end
      // paged
      // but if we cant say otherwise, then it might be paged

      auto KBstart = KnownBits::makeConstant(APInt(64, start));
      auto KBend = KnownBits::makeConstant(APInt(64, end));

      if (KnownBits::uge(KBofAddress, KBstart) &&
          KnownBits::ult(KBofAddress, KBend)) {
        return MEMORY_PAGED;
      }

      if (!(KnownBits::uge(KBofAddress, KBend) ||
            KnownBits::ult(KBofAddress, KBstart))) {
        return MEMORY_MIGHT_BE_PAGED;
      }
    }

    return MEMORY_NOT_PAGED;
  }

  void pagedCheck(Value* address, const DataLayout& DL) {
    isPaged paged = isValuePaged(address, DL);
    switch (paged) {
    case MEMORY_NOT_PAGED: {
      cout << "\nmemory is not paged, so we(more likely) or the program "
              "probably do some incorrect stuff "
              "we abort to avoid incorrect output\n"
           << endl;
      abort();
      break;
    }
    case MEMORY_MIGHT_BE_PAGED: {
      // something something if flag turned on print some data
      break;
    }
    case MEMORY_PAGED: {
      // nothing
      break;
    }
    }
  }

  void loadMemoryOp(LoadInst* inst) {
    auto ptr = inst->getPointerOperand();
    if (!isa<GetElementPtrInst>(ptr))
      return;

    auto gepInst = cast<GetElementPtrInst>(ptr);
    auto gepPtr = gepInst->getPointerOperand();
    if (gepPtr != getMemory())
      return;

    auto gepOffset = gepInst->getOperand(1);

    pagedCheck(gepOffset,
               inst->getParent()->getParent()->getParent()->getDataLayout());
    return;
  }

  // rename func name to indicate its only for store
  void insertMemoryOp(StoreInst* inst) {
    memInfos.push_back(inst);

    auto ptr = inst->getPointerOperand();
    if (!isa<GetElementPtrInst>(ptr))
      return;

    auto gepInst = cast<GetElementPtrInst>(ptr);
    auto gepPtr = gepInst->getPointerOperand();
    if (gepPtr != getMemory())
      return;

    auto gepOffset = gepInst->getOperand(1);

    pagedCheck(gepOffset,
               inst->getParent()->getParent()->getParent()->getDataLayout());

    if (!isa<ConstantInt>(gepOffset)) // we also want to do operations with the
                                      // memory when we can assume a range or
                                      // writing to an unk location (ofc paged)
      return;

    auto gepOffsetCI = cast<ConstantInt>(gepOffset);

    VirtualStack.addValueReference(inst, inst->getValueOperand(),
                                   gepOffsetCI->getZExtValue());
    BinaryOperations::WriteTo(gepOffsetCI->getZExtValue());
  }

  bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2,
                uint64_t size2) {
    return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
  }

  uint64_t createmask(uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) {

    auto start_overlap = max(a1, b1);
    auto end_overlap = min(a2, b2);
    int64_t diffStart = a1 - b1;

    printvalue2(start_overlap) printvalue2(end_overlap);
    // If there is no overlap
    if (start_overlap > end_overlap)
      return 0;

    auto num_bytes = end_overlap - start_overlap;
    // mask =>
    uint64_t mask = 0xffffffffffffffff >>
                    (64 - (num_bytes * 8)); // adjust mask for bytesize
    printvalue2(diffStart);
    if (diffStart <= 0)
      return mask;

    auto diffShift = abs(diffStart);

    printvalue2(mask) mask <<= (diffShift) * 8; // get the shifted mask
    printvalue2(mask)

        mask ^= -(diffStart < 0); // if diff was -, get the negative of mask
    printvalue2(mask)

        return mask;
  }

  struct PairHash {
    std::size_t operator()(const std::pair<llvm::Value*, int>& pair) const {
      // Combine the hashes of the two elements
      return hash<llvm::Value*>{}(pair.first) ^ hash<int>{}(pair.second);
    }
  };

  void removeDuplicateOffsets(vector<Instruction*>& vec) {
    if (vec.empty())
      return;

    unordered_map<pair<Value*, int>, Instruction*, PairHash> latestOffsets;
    vector<Instruction*> uniqueInstructions;
    uniqueInstructions.reserve(
        vec.size()); // reserve space assuming all could be unique
    latestOffsets.reserve(
        vec.size()); // reserve space assuming all could be unique

    for (auto it = vec.rbegin(); it != vec.rend(); ++it) {
      auto inst = cast<StoreInst>(*it);
      auto GEPval = inst->getPointerOperand();
      auto valOp = inst->getValueOperand();
      int size = valOp->getType()->getIntegerBitWidth();
      auto GEPInst = cast<GetElementPtrInst>(GEPval);
      auto offset = GEPInst->getOperand(1);
      auto pair = make_pair(offset, size);

      if (latestOffsets.emplace(pair, *it).second) {
        uniqueInstructions.push_back(*it);
      }
    }

    vec.assign(uniqueInstructions.rbegin(), uniqueInstructions.rend());
  }

  void removeFutureInsts(vector<Instruction*>& vec, LoadInst* load) {
    // binary search
    auto it = std::lower_bound(
        vec.begin(), vec.end(), load,
        [](Instruction* a, Instruction* b) { return comesBefore(a, b, *DT); });

    if (it != vec.end()) {
      vec.erase(it, vec.end());
    }
  }

  Value* solveLoad(LoadInst* load, bool buildTime) {
    Function* F = load->getFunction();
    printvalue(load);

    // replace this
    auto LoadMemLoc = MemoryLocation::get(load);

    const Value* loadPtr = LoadMemLoc.Ptr;
    LocationSize loadsize = LoadMemLoc.Size;

    auto cloadsize = loadsize.getValue();

    auto loadPtrGEP = cast<GetElementPtrInst>(loadPtr);

    auto loadPointer = loadPtrGEP->getPointerOperand();
    auto loadOffset = loadPtrGEP->getOperand(1);
    printvalue(loadOffset);
    if (buildTime) {
      if (isa<ConstantInt>(loadOffset)) {
        auto loadOffsetCI = cast<ConstantInt>(loadOffset);

        auto loadOffsetCIval = loadOffsetCI->getZExtValue();

        IRBuilder<> builder(load);
        auto valueExtractedFromVirtualStack =
            VirtualStack.retrieveCombinedValue(builder, loadOffsetCIval,
                                               cloadsize);
        if (valueExtractedFromVirtualStack) {
          return valueExtractedFromVirtualStack;
        }
      }
    } else
      GEPStoreTracker::updateDomTree(*F);

    // create a new vector with only leave what we care about
    vector<Instruction*> clearedMemInfos;

    clearedMemInfos = memInfos;

    //
    // idea:
    // for runtime, we can optimize by having a map, that way we will only
    // have the last inst
    //
    // idea 2:
    // create a set, only take a range from it
    //

    if (!buildTime)
      removeFutureInsts(clearedMemInfos, load);

    removeDuplicateOffsets(clearedMemInfos);

    Value* retval = nullptr;

    for (auto inst : clearedMemInfos) {

      // we are only interested in previous instructions

      if (!buildTime)
        if (comesBefore(load, inst, *DT))
          break;

      // replace it with something more efficent
      // auto MemLoc = MemoryLocation::get(inst);

      StoreInst* storeInst = cast<StoreInst>(inst);
      auto memLocationValue = storeInst->getPointerOperand();

      auto memLocationGEP = cast<GetElementPtrInst>(memLocationValue);

      auto pointer = memLocationGEP->getOperand(0);
      auto offset = memLocationGEP->getOperand(1);

      if (pointer != loadPointer)
        break;

      // find a way to compare with unk values, we are also interested
      // when offset in unk ( should be a rare case )
      if (!isa<ConstantInt>(offset) || !isa<ConstantInt>(loadOffset))
        continue;

      uint64_t memOffsetValue = cast<ConstantInt>(offset)->getZExtValue();
      uint64_t loadOffsetValue = cast<ConstantInt>(loadOffset)->getZExtValue();

      uint64_t diff = memOffsetValue - loadOffsetValue;

      // this is bytesize, not bitsize
      uint64_t storeBitSize =
          storeInst->getValueOperand()->getType()->getIntegerBitWidth() / 8;

      if (overlaps(loadOffsetValue, cloadsize, memOffsetValue, storeBitSize)) {

        printvalue2(diff) printvalue2(memOffsetValue);
        printvalue2(loadOffsetValue) printvalue2(storeBitSize);

        auto storedInst = inst->getOperand(0);
        if (!retval)
          retval = ConstantInt::get(load->getType(), 0);

        Value* mask = ConstantInt::get(
            storedInst->getType(),
            createmask(loadOffsetValue, loadOffsetValue + cloadsize,
                       memOffsetValue, memOffsetValue + storeBitSize));

        printvalue(mask);

        IRBuilder<> builder(load);
        // we dont have to calculate knownbits if its a constant
        auto maskedinst = createAndFolder(builder, storedInst, mask,
                                          inst->getName() + ".maskedinst");

        printvalue(storedInst);
        printvalue(mask);
        printvalue(maskedinst);
        if (maskedinst->getType()->getScalarSizeInBits() <
            retval->getType()->getScalarSizeInBits())
          maskedinst = builder.CreateZExt(maskedinst, retval->getType());

        if (mask->getType()->getScalarSizeInBits() <
            retval->getType()->getScalarSizeInBits())
          mask = builder.CreateZExt(mask, retval->getType());

        printvalue(maskedinst);
        printvalue2(diff);
        // move the mask?
        if (diff > 0) {
          maskedinst = createShlFolder(builder, maskedinst, (diff) * 8);
          mask = createShlFolder(builder, mask, (diff) * 8);
        } else if (diff < 0) {
          maskedinst =
              createLShrFolder(builder, maskedinst, -(diff) * 8, "clevername");
          mask = createLShrFolder(builder, mask, -(diff) * 8, "stupidname");
        }
        // maskedinst = maskedinst
        // maskedinst = 0x4433221100000000
        printvalue(maskedinst);
        maskedinst = builder.CreateZExtOrTrunc(maskedinst, retval->getType());
        printvalue(maskedinst);

        printvalue(mask);

        // clear mask from retval so we can merge
        // this will be a NOT operation for sure

        auto reverseMask = builder.CreateNot(mask);

        printvalue(reverseMask);

        auto cleared_retval =
            createAndFolder(builder, retval,
                            builder.CreateTrunc(reverseMask, retval->getType()),
                            retval->getName() + ".cleared");
        // cleared_retval = 0 & 0; clear retval
        // cleared_retval = retval & 0xff_ff_ff_ff_00_00_00_00

        retval = createOrFolder(builder, cleared_retval, maskedinst,
                                cleared_retval->getName() + ".merged");
        // retval = builder.CreateTrunc(retval, load->getType());
        printvalue(cleared_retval);
        printvalue(maskedinst);
        // retval = cleared_retval | maskedinst =|= 0 |
        // 0x1122334455667788 retval = cleared_retval | maskedinst =|=
        // 0x55667788 | 0x4433221100000000

        if (retval)
          if (retval->getType()->getScalarSizeInBits() >
              load->getType()->getScalarSizeInBits())
            retval = builder.CreateTrunc(retval, load->getType());

        printvalue(inst);
        auto retvalload = retval;
        printvalue(cleared_retval);
        printvalue(retvalload);
        debugging::doIfDebug([&]() { cout << "-------------------\n"; });
      }
    }
    return retval;
  }

}; // namespace GEPStoreTracker

// some stuff about memory
// partial load example
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 4
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 55 [4] 44 33 22
// 11 [8] store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m3 => [0] 88 77 66 55 [4] 44
// 33 22 11 [8] AC AB FF EE [12] DD CC BB AA [16] %x = load i64, ptr %m2 => [0]
// 88 77 66 55 [4] 44 33 22 11 [8] AC AB FF EE [12] DD CC BB AA [16] now: %x =
// 44 33 22 11 AC AB FF EE => 0xEE_FF_AB_AC_11_22_33_44 %p1 =
// 0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_FF_00_00_00_00 %p2 =
// 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_00_00_FF_FF_FF_FF %p3 = 0 %p1.shift = %p1
// >> 4(diff)*8 %p2.shift = %p2 << 4(diff)*8 %p4 = %p1.shift | %p2.shift
//
// overwriting example
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 2
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 [2] 66 55 [4] 44 33
// 22 11 [8] store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m2 => [0] 88 77 [2] AC AB
// [4] FF EE DD CC [8] BB AA [10] %x = load i64, ptr %m1 => [0] 88 77 [2] AC AB
// [4] FF EE DD CC [8] BB AA [10] now: %x = 88 77 AC AB FF EE DD CC =>
// 0xCC_DD_EE_FF_AB_AC_11_22 %p1 = 0x11_22_33_44_55_66_77_88 & -1 %p2 =
// 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_FF_FF_FF_FF_FF_FF %p2.shifted = %p2 <<
// 2*8 %mask.shifted = 0x00_00_FF_FF_FF_FF_FF_FF << 2*8 =>
// 0xFF_FF_FF_FF_FF_FF_00_00 %reverse.mask.shifted = 0xFF_FF %p1.masked = %p1 &
// %reverse.mask.shifted %retval = %p2.shifted | %p1.masked
//
// overwriting example WITH DIFFERENT TYPES
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 3
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33 22
// [7] 11 [8] store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66 [3]
// DD CC BB AA [7] 11 [8] %x = load i64, ptr %m1                       => [0] 88
// 77 66 [3] DD CC BB AA [7] 11 [8] now: %x=[0] 88 77 66 [3] DD CC BB AA [7] 11
// [8] => 0x11_AA_BB_CC_DD_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88 & -1 %p2 =
// 0xAA_BB_CC_DD & 0xFF_FF_FF_FF %p2.shifted = %p2 << 1*8                 =>
// 0xAA_BB_CC_DD << 8 => 0x_AA_BB_CC_DD_00 %mask.shifted = 0xFF_FF_FF_FF << 1*8
// => 0x00_00_00_FF_FF_FF_FF_00 %reverse.mask.shifted =
// 0xFF_FF_FF_00_00_00_00_FF %p1.masked = %p1 & %reverse.mask.shifted =>
// 0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_00_00_00_00_FF =>
// 0x11_22_33_00_00_00_00_88 %retval = %p2.shifted | %p1.masked       =>
// 0x11_22_33_00_00_00_00_88 | 0x00_00_00_AA_BB_CC_DD_00 =>
// 0x11_22_33_AA_BB_CC_DD_88
//
// PARTIAL overwriting example WITH DIFFERENT TYPES v1
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 6
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33 [6]
// 22 11 [8] store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66 [3] 55
// 44 33 [6] DD CC [8] BB AA [10] %x = load i64, ptr %m1 => [0] 88 77 66 [3] 55
// 44 33 [6] DD CC [8] BB AA [10] now: %x=[0] 88 77 66 [3] 55 44 33 [6] DD CC
// [8] => 0xCC_DD_33_44_55_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88 & -1 %p2 =
// 0xAA_BB_CC_DD & 0x00_00_FF_FF %p2.shifted = %p2 << 6*8                 =>
// 0xCC_DD << 48 => 0xCC_DD_00_00_00_00_00_00 %mask.shifted = 0xFF_FF_FF_FF <<
// 6*8     => 0xFF_FF_00_00_00_00_00_00 %reverse.mask.shifted =
// 0x00_00_FF_FF_FF_FF_FF_FF %p1.masked = %p1 & %reverse.mask.shifted =>
// 0x11_22_33_44_55_66_77_88 & 0x00_00_FF_FF_FF_FF_FF_FF =>
// 0x00_00_33_44_55_66_77_88 %retval = %p2.shifted | %p1.masked       =>
// 0x00_00_33_44_55_66_77_88 | 0xCC_DD_00_00_00_00_00_00 =>
// 0xCC_DD_33_44_55_66_77_88
//
//
// PARTIAL overwriting example WITH DIFFERENT TYPES v2
//
//
//
// %m1 = getelementptr i8, %memory, i64 8
// %m2 = getelementptr i8, %memory, i64 7
// %m3 = getelementptr i8, %memory, i64 16
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [7] ?? [8] 88 77 66 [11] 55
// 44 33 22 11 [16] store i32 0xAA_BB_CC_DD, ptr %m2             => [7] DD [8]
// CC BB AA [11] 55 44 33 22 11 [16] %x = load i64, ptr %m1 => [7] DD [8] CC BB
// AA [11] 55 44 33 22 11 [16] now: %x=[7] DD [8] CC BB AA [11] 55 44 33 22 11
// [16] => 0xCC_DD_33_44_55_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88 & -1 %p2 =
// 0xAA_BB_CC_DD & 0xFF_FF_FF_00 (0xFF ^ -1) %p2.shifted = %p2 << 1*8 =>
// 0xAA_BB_CC_00 >> 8 => 0xAA_BB_CC => 0x00_00_00_00_00_AA_BB_CC %mask.shifted =
// 0xFF_FF_FF_00 >> 1*8     => 0xFF_FF_FF %reverse.mask.shifted =
// 0xFF_FF_FF_FF_FF_00_00_00 %p1.masked = %p1 & %reverse.mask.shifted =>
// 0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_FF_FF_00_00_00 =>
// 0x11_22_33_44_55_00_00_00 %retval = %p2.shifted | %p1.masked       =>
// 0x11_22_33_44_55_00_00_00 | 0xAA_BB_CC                =>
// 0x11_22_33_44_55_AA_BB_CC
//
//
// creating masks:
// orgload = 0<->8
// currentstore = 4<->8
// size = 32bits
// mask will be:
// 0xFF_FF_FF_FF_00_00_00_00
//
// orgload = 0<->8
// currentstore = 3<->7
// size = 32bits
// mask will be:
// 0x00_FF_FF_FF_FF_00_00_00
//
// orgload = 0<->8
// currentstore = 6<->10
// size = 32bits
// mask will be:
// 0xFF_FF_00_00_00_00_00_00
//
// orgload = 10<->18
// currentstore = 8<->16
// size = 32bits
// mask will be:
// 0x00_00_00_00_00_00_FF_FF
//
// mask generation:
// a1 = loadStart
// a2 = loadEnd
// b1 = storeStart
// b2 = storeEnd
//  a1, a2, b1, b2
// (assuming they overlap)
// [6 = b1] [7] [8 = a1] [9] [10 = b2] [11] [12 = a2]
//    -      -      +     +     -       /       /
// normal mask for b =  0xFF_FF_00_00
// clear  mask for a = ~0x00_00_FF_FF
//
// shift size = 2 (a1-b1, since its +, shift to right)
//
//
// [8 = a1] [9] [10] [11 = b1] [12 = a2] [13] [14 = b2]
//    -      -    -      +        /        /      /
//
// normal mask for b =  0x00_00_00_FF (lowest byte gets saved)
// clear  mask for a = ~0xFF_00_00_00 (only highest byte gets cleared)
//
// shift size = -3 (a1-b1, since its -, shift to left)
//
// first iteration in loop
// store = getstore(currentStore)
// createMask( diff )
// shiftStore  = Store1 << diff
// shiftedmask = mask << diff
// reverseMask = ~shiftedmask
// retvalCleared = retval & reverseMask
// retval = retvalCleared | shiftStore
// second iteration in loop
//
// store = getstore(currentStore)
// createMask( diff )
// shiftStore  = Store1 << diff
// shiftedmask = mask << diff
// reverseMask = ~shiftedmask
// retvalCleared = retval & reverseMask
// retval = retvalCleared | shiftStore
//
//
//