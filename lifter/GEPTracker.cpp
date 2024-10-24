#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"
#include "lifterClass.h"
#include "nt/nt_headers.hpp"
#include "utils.h"
#include <iostream>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/BasicAliasAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/WithCache.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/KnownBits.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Transforms/Utils/SCCPSolver.h>

namespace BinaryOperations {

  // wtf man
  ZyanU8* data_g;

  void initBases(ZyanU8* data) { data_g = data; }

  void getBases(ZyanU8** data) { *data = data_g; }

  const char* getName(uint64_t offset) {
    auto dosHeader = (win::dos_header_t*)data_g;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)data_g + dosHeader->e_lfanew);
    auto rvaOffset = FileHelper::RvaToFileOffset(ntHeaders, offset);
    return (const char*)data_g + rvaOffset;
  }
  bool isImport(uint64_t addr) {
    APInt tmp;
    auto dosHeader = (win::dos_header_t*)data_g;
    auto ntHeaders =
        (win::nt_headers_x64_t*)((uint8_t*)data_g + dosHeader->e_lfanew);
    return readMemory(ntHeaders->optional_header.image_base + addr, 1, tmp);
  }

  DenseSet<uint64_t> MemWrites;

  bool isWrittenTo(uint64_t addr) {
    return MemWrites.find(addr) != MemWrites.end();
  }
  void WriteTo(uint64_t addr) { MemWrites.insert(addr); }

  // sections
  bool readMemory(uint64_t addr, unsigned byteSize, APInt& value) {

    uint64_t mappedAddr = FileHelper::address_to_mapped_address(addr);
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

void lifterClass::addValueReference(Value* value, uint64_t address) {
  unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
  for (unsigned i = 0; i < valueSizeInBytes; i++) {

    BinaryOperations::WriteTo(address + i);
    printvalue2(address + i);
    buffer[address + i] = ValueByteReference(value, i);
    printvalue(value);
    printvalue2((uint64_t)address + i);
  }
}

Value* lifterClass::retrieveCombinedValue(uint64_t startAddress,
                                          uint8_t byteCount, Value* orgLoad) {
  LLVMContext& context = builder.getContext();
  if (byteCount == 0) {
    return nullptr;
  }

  // bool contiguous = true;
  SmallVector<ValueByteReferenceRange, 64>
      values; // we can just create an array here
  for (uint8_t i = 0; i < byteCount; ++i) {
    uint64_t currentAddress = startAddress + i;

    auto isDifferentReferenceOrDiscontinuousOffset =
        [this](const ValueByteReferenceRange& lastRef,
               uint64_t currentAddress) {
          const auto& currentValue = buffer[currentAddress];
          return lastRef.ref.value != currentValue.value ||
                 lastRef.ref.byteOffset !=
                     currentValue.byteOffset - (lastRef.end - lastRef.start);
        };

    bool isEmpty = values.empty();
    bool isContained = buffer.contains(currentAddress);
    bool isLastReference = !isEmpty && values.back().isRef;
    // push if
    if (isEmpty || (isContained && isLastReference &&
                    isDifferentReferenceOrDiscontinuousOffset(
                        values.back(), currentAddress))) {
      if (buffer.contains(currentAddress)) {
        values.push_back(
            ValueByteReferenceRange(buffer[currentAddress], i, i + 1));
      } else {
        values.push_back(ValueByteReferenceRange(currentAddress, i, i + 1));
      }
    } else {
      ++values.back().end;
    }
  }

  Value* result = ConstantInt::get(Type::getIntNTy(context, byteCount * 8), 0);

  int m = 0;
  for (auto v : values) {
    Value* byteValue = nullptr;
    uint8_t bytesize = v.end - v.start;

    APInt mem_value(1, 0);
    if (v.isRef) {
      byteValue = extractBytes(v.ref.value, v.ref.byteOffset,
                               v.ref.byteOffset + bytesize);
    } else if (!v.isRef && BinaryOperations::readMemory(v.memoryAddress,
                                                        bytesize, mem_value)) {
      byteValue = builder.getIntN(bytesize * 8, mem_value.getZExtValue());
    } else if (!v.isRef) {
      // llvm_unreachable_internal("uh...");
      byteValue = extractBytes(orgLoad, m, m + bytesize);
    }
    if (byteValue) {
      printvalue(byteValue);

      Value* shiftedByteValue = createShlFolder(

          createZExtFolder(byteValue, Type::getIntNTy(context, byteCount * 8)),
          APInt(byteCount * 8, m * 8));
      result = createOrFolder(result, shiftedByteValue, "extractbytesthing");
    }
    m += bytesize;
  }

  return result;
}

Value* lifterClass::extractBytes(Value* value, uint8_t startOffset,
                                 uint8_t endOffset) {
  LLVMContext& context = builder.getContext();

  if (!value) {
    return ConstantInt::get(
        Type::getIntNTy(context, (endOffset - startOffset) * 8), 0);
  }

  uint8_t byteCount = endOffset - startOffset;

  uint8_t shiftAmount = startOffset * 8;

  printvalue2(endOffset);

  printvalue2(startOffset);
  printvalue2(byteCount);
  printvalue2(shiftAmount);

  Value* shiftedValue = createLShrFolder(
      value, APInt(value->getType()->getIntegerBitWidth(), shiftAmount),
      "extractbytes");
  printvalue(value);
  printvalue(shiftedValue);

  Value* truncatedValue =
      createTruncFolder(shiftedValue, Type::getIntNTy(context, byteCount * 8));
  return truncatedValue;
}

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

    for (Argument& AI : function->args())
      solver->markOverdefined(&AI);
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

isPaged lifterClass::isValuePaged(Value* address, Instruction* ctxI) {
  if (isa<ConstantInt>(address)) {
    return isMemPaged(cast<ConstantInt>(address)->getZExtValue())
               ? MEMORY_PAGED
               : MEMORY_NOT_PAGED;
  }
  auto KBofAddress = analyzeValueKnownBits(address, ctxI);

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

void lifterClass::pagedCheck(Value* address, Instruction* ctxI) {
  isPaged paged = isValuePaged(address, ctxI);

  switch (paged) {
  case MEMORY_NOT_PAGED: {
    printvalueforce(address);
    printvalueforce2(instruction.mnemonic);
    printvalueforce2(blockInfo.runtime_address);
    debugging::doIfDebug([&]() {
      std::string Filename = "output_paged_error.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder.GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
    });
    UNREACHABLE("\nmemory is not paged, so we(more likely) or the program "
                "probably do some incorrect stuff "
                "we abort to avoid incorrect output\n");
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

void lifterClass::loadMemoryOp(LoadInst* inst) {
  auto ptr = inst->getPointerOperand();
  if (!isa<GetElementPtrInst>(ptr))
    return;

  auto gepInst = cast<GetElementPtrInst>(ptr);
  auto gepPtr = gepInst->getPointerOperand();
  if (gepPtr != getMemory())
    return;

  auto gepOffset = gepInst->getOperand(1);

  pagedCheck(gepOffset, inst);
  return;
}

// rename func name to indicate its only for store
void lifterClass::insertMemoryOp(StoreInst* inst) {
  memInfos.push_back(inst);

  auto ptr = inst->getPointerOperand();
  if (!isa<GetElementPtrInst>(ptr))
    return;

  auto gepInst = cast<GetElementPtrInst>(ptr);
  auto gepPtr = gepInst->getPointerOperand();
  if (gepPtr != getMemory())
    return;

  auto gepOffset = gepInst->getOperand(1);

  pagedCheck(gepOffset, inst);

  if (!isa<ConstantInt>(gepOffset)) // we also want to do operations with the
                                    // memory when we can assume a range or
                                    // writing to an unk location (ofc paged)
    return;

  auto gepOffsetCI = cast<ConstantInt>(gepOffset);

  addValueReference(inst->getValueOperand(), gepOffsetCI->getZExtValue());
  BinaryOperations::WriteTo(gepOffsetCI->getZExtValue());
}

bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2, uint64_t size2) {
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
  uint64_t mask =
      0xffffffffffffffff >> (64 - (num_bytes * 8)); // adjust mask for bytesize
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

set<APInt, APIntComparator>
lifterClass::getPossibleValues(const llvm::KnownBits& known,
                               unsigned max_unknown) {

  if (max_unknown >= 4) {
    debugging::doIfDebug([&]() {
      std::string Filename = "output_too_many_unk.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder.GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
    });
    printvalueforce2(max_unknown);
    UNREACHABLE("There is a very huge chance that this shouldnt happen");
  }
  llvm::APInt base = known.One;
  llvm::APInt unknowns = ~(known.Zero | known.One);
  unsigned numBits = known.getBitWidth();

  set<APInt, APIntComparator> values;

  llvm::APInt combo(unknowns.getBitWidth(), 0);
  for (uint64_t i = 0; i < (1ULL << max_unknown); ++i) {
    llvm::APInt temp = base;
    for (unsigned j = 0, currentBit = 0; j < numBits; ++j) {
      if (unknowns[j]) {
        temp.setBitVal(j, (i >> currentBit) & 1);
        currentBit++;
      }
    }

    values.insert(temp);
  }

  return values;
}

std::set<APInt, APIntComparator>
calculatePossibleValues(std::set<APInt, APIntComparator> v1,
                        std::set<APInt, APIntComparator> v2,
                        Instruction* inst) {
  std::set<APInt, APIntComparator> res;
  for (const auto& vv1 : v1) {
    printvalue2(vv1);
    for (const auto& vv2 : v2) {
      printvalue2(vv2);
      switch (inst->getOpcode()) {
      case Instruction::Add: {
        res.insert(vv1 + vv2);
        break;
      }
      case Instruction::Sub: {
        res.insert(vv1 - vv2);
        break;
      }
      case Instruction::Mul: {
        res.insert(vv1 * vv2);
        break;
      }
      case Instruction::LShr: {
        res.insert(vv1.lshr(vv2));
        break;
      }
      case Instruction::AShr: {
        res.insert(vv1.ashr(vv2));
        break;
      }
      case Instruction::Shl: {
        res.insert(vv1.shl(vv2));
        break;
      }
      case Instruction::UDiv: {
        if (!vv2.isZero()) {
          res.insert(vv1.udiv(vv2));
        }
        break;
      }
      case Instruction::URem: {
        res.insert(vv1.urem(vv2));
        break;
      }
      case Instruction::SDiv: {
        if (!vv2.isZero()) {
          res.insert(vv1.sdiv(vv2));
        }
        break;
      }
      case Instruction::SRem: {
        res.insert(vv1.srem(vv2));
        break;
      }
      case Instruction::And: {
        res.insert(vv1 & vv2);
        break;
      }
      case Instruction::Or: {
        res.insert(vv1 | vv2);
        break;
      }
      case Instruction::Xor: {
        res.insert(vv1 ^ vv2);
        break;
      }
      case Instruction::ICmp: {
        switch (cast<ICmpInst>(inst)->getPredicate()) {
        case llvm::CmpInst::ICMP_EQ: {
          res.insert(APInt(64, vv1.eq(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_NE: {
          res.insert(APInt(64, vv1.ne(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_SLE: {
          res.insert(APInt(64, vv1.sle(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_SLT: {
          res.insert(APInt(64, vv1.slt(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_ULE: {
          res.insert(APInt(64, vv1.ule(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_ULT: {
          res.insert(APInt(64, vv1.ult(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_SGE: {
          res.insert(APInt(64, vv1.sge(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_SGT: {
          res.insert(APInt(64, vv1.sgt(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_UGE: {
          res.insert(APInt(64, vv1.uge(vv2)));
          break;
        }
        case llvm::CmpInst::ICMP_UGT: {
          res.insert(APInt(64, vv1.ugt(vv2)));
          break;
        }
        default: {
          outs() << "\n : " << cast<ICmpInst>(inst)->getPredicate();
          outs().flush();
          UNREACHABLE(
              "Unsupported operation in calculatePossibleValues ICMP.\n");
          break;
        }
        }
        break;
      }
      default:
        outs() << "\n : " << inst->getOpcode();
        outs().flush();
        UNREACHABLE("Unsupported operation in calculatePossibleValues.\n");
        break;
      }
    }
  }
  return res;
}

set<APInt, APIntComparator> lifterClass::computePossibleValues(Value* V,
                                                               uint8_t Depth) {
  printvalue2(Depth);
  if (Depth > 16) {
    debugging::doIfDebug([&]() {
      std::string Filename = "output_depth_exceeded.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder.GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
    });
    UNREACHABLE("Depth exceeded");
  }
  set<APInt, APIntComparator> res;
  printvalue(V);
  if (auto v_ci = dyn_cast<ConstantInt>(V)) {
    res.insert(v_ci->getValue());
    return res;
  }
  if (auto v_inst = dyn_cast<Instruction>(V)) {

    if (v_inst->getNumOperands() == 1)
      return computePossibleValues(v_inst->getOperand(0), Depth + 1);

    if (v_inst->getOpcode() == Instruction::Select) {
      auto cond = v_inst->getOperand(0);
      auto trueValue = v_inst->getOperand(1);
      auto falseValue = v_inst->getOperand(2);

      auto kb = analyzeValueKnownBits(cond, v_inst);
      printvalue2(kb);

      if (kb.isZero()) {
        auto falseValues = computePossibleValues(falseValue, Depth + 1);

        res.insert(falseValues.begin(), falseValues.end());
        return res;
      }
      if (kb.isNonZero()) {
        auto falseValues = computePossibleValues(falseValue, Depth + 1);

        res.insert(falseValues.begin(), falseValues.end());
        return res;
      }
      auto trueValues = computePossibleValues(trueValue, Depth + 1);
      // Combine all possible values from both branches
      res.insert(trueValues.begin(), trueValues.end());

      auto falseValues = computePossibleValues(falseValue, Depth + 1);

      res.insert(falseValues.begin(), falseValues.end());
      return res;
    }
    auto op1 = v_inst->getOperand(0);
    auto op2 = v_inst->getOperand(1);
    auto op1_knownbits = analyzeValueKnownBits(op1, v_inst);
    unsigned int op1_unknownbits_count = llvm::popcount(
        ~(op1_knownbits.One | op1_knownbits.Zero).getZExtValue());

    auto op2_knownbits = analyzeValueKnownBits(op2, v_inst);
    unsigned int op2_unknownbits_count = llvm::popcount(
        ~(op2_knownbits.One | op2_knownbits.Zero).getZExtValue());
    printvalue2(analyzeValueKnownBits(V, v_inst));
    auto v_knownbits = analyzeValueKnownBits(v_inst, v_inst);
    unsigned int res_unknownbits_count =
        llvm::popcount(~(v_knownbits.One | v_knownbits.Zero).getZExtValue()) -
        64 + v_knownbits.getBitWidth();

    auto total_unk = ~((op1_knownbits.One | op1_knownbits.Zero) &
                       (op2_knownbits.One | op2_knownbits.Zero));

    unsigned int total_unknownbits_count =
        llvm::popcount(total_unk.getZExtValue()) - 64 + total_unk.getBitWidth();
    printvalue2(v_knownbits);
    printvalue2(op1_knownbits);
    printvalue2(op2_knownbits);
    printvalue2(res_unknownbits_count);
    printvalue2(op1_unknownbits_count);
    printvalue2(op2_unknownbits_count);
    printvalue2(total_unknownbits_count);

    if ((res_unknownbits_count >= total_unknownbits_count) &&
        res_unknownbits_count != 1) {
      auto v1 = computePossibleValues(op1, Depth + 1);
      auto v2 = computePossibleValues(op2, Depth + 1);

      printvalue(v_inst);
      printvalue2(v_knownbits);
      printvalue(op1);
      for (auto& vv1 : v1) {
        printvalue2(op1_knownbits);
        printvalue2(vv1);
      }
      printvalue(op2);
      for (auto& vv2 : v2) {
        printvalue2(op2_knownbits);
        printvalue2(vv2);
      }
      return calculatePossibleValues(v1, v2, v_inst);
    }
    return getPossibleValues(v_knownbits, res_unknownbits_count);
  }
  return res;
}

Value* lifterClass::solveLoad(LoadInst* load) {
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

  // if we know all the stores, we can use our buffer
  // however, if we dont know all the stores
  // we have to if check each store overlaps with our load
  // specifically for indirect stores
  if (isa<ConstantInt>(loadOffset)) {
    auto loadOffsetCI = cast<ConstantInt>(loadOffset);

    auto loadOffsetCIval = loadOffsetCI->getZExtValue();

    auto valueExtractedFromVirtualStack =
        retrieveCombinedValue(loadOffsetCIval, cloadsize, load);
    if (valueExtractedFromVirtualStack) {
      return valueExtractedFromVirtualStack;
    }
  } else {
    // Get possible values from loadOffset

    if (isa<SelectInst>(loadOffset)) { // dyn_cast
      auto select_inst = cast<SelectInst>(loadOffset);
      if (isa<ConstantInt>(select_inst->getTrueValue()) &&
          isa<ConstantInt>(select_inst->getFalseValue()))
        // we should be able to do this whether
        // this is a constant or not
        return createSelectFolder(
            select_inst->getCondition(),
            retrieveCombinedValue(
                cast<ConstantInt>(select_inst->getTrueValue())->getZExtValue(),
                cloadsize, load),
            retrieveCombinedValue(
                cast<ConstantInt>(select_inst->getFalseValue())->getZExtValue(),
                cloadsize, load));
    }
    auto possibleValues = computePossibleValues(loadOffset, 0);

    llvm::Value* selectedValue = nullptr;

    for (auto possibleValue : possibleValues) { // rename

      auto isPaged = isMemPaged(possibleValue.getZExtValue());
      if (!isPaged)
        continue;
      printvalue2(possibleValue);
      auto possible_values_from_mem =
          retrieveCombinedValue(possibleValue.getZExtValue(), cloadsize, load);
      printvalue2((uint64_t)cloadsize);
      printvalue(possible_values_from_mem);

      if (selectedValue == nullptr) {
        selectedValue = possible_values_from_mem;
      } else {

        llvm::Value* comparison = createICMPFolder(
            CmpInst::ICMP_EQ, loadOffset,
            llvm::ConstantInt::get(loadOffset->getType(), possibleValue));
        printvalue(comparison);
        selectedValue =
            createSelectFolder(comparison, possible_values_from_mem,
                               selectedValue, "conditional-mem-load");
      }
    }
    return selectedValue;
  }

  // create a new vector with only leave what we care about
  vector<Instruction*> clearedMemInfos;

  clearedMemInfos = memInfos;
  removeDuplicateOffsets(clearedMemInfos);

  Value* retval = nullptr;

  for (auto inst : clearedMemInfos) {

    // we are only interested in previous instructions

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

      // we dont have to calculate knownbits if its a constant
      auto maskedinst =
          createAndFolder(storedInst, mask, inst->getName() + ".maskedinst");

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
        maskedinst = createShlFolder(maskedinst, (diff) * 8);
        mask = createShlFolder(mask, (diff) * 8);
      } else if (diff < 0) {
        maskedinst = createLShrFolder(maskedinst, -(diff) * 8, "clevername");
        mask = createLShrFolder(mask, -(diff) * 8, "stupidname");
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

      auto cleared_retval = createAndFolder(
          retval, builder.CreateTrunc(reverseMask, retval->getType()),
          retval->getName() + ".cleared");
      // cleared_retval = 0 & 0; clear retval
      // cleared_retval = retval & 0xff_ff_ff_ff_00_00_00_00

      retval = createOrFolder(cleared_retval, maskedinst,
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

// some stuff about memory
// partial load example
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 4
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 55 [4] 44 33
// 22 11 [8] store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m3 => [0] 88 77 66 55
// [4] 44 33 22 11 [8] AC AB FF EE [12] DD CC BB AA [16] %x = load i64, ptr
// %m2 => [0] 88 77 66 55 [4] 44 33 22 11 [8] AC AB FF EE [12] DD CC BB AA
// [16] now: %x = 44 33 22 11 AC AB FF EE => 0xEE_FF_AB_AC_11_22_33_44 %p1 =
// 0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_FF_00_00_00_00 %p2 =
// 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_00_00_FF_FF_FF_FF %p3 = 0 %p1.shift =
// %p1
// >> 4(diff)*8 %p2.shift = %p2 << 4(diff)*8 %p4 = %p1.shift | %p2.shift
//
// overwriting example
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 2
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 [2] 66 55 [4] 44
// 33 22 11 [8] store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m2 => [0] 88 77 [2]
// AC AB [4] FF EE DD CC [8] BB AA [10] %x = load i64, ptr %m1 => [0] 88 77
// [2] AC AB [4] FF EE DD CC [8] BB AA [10] now: %x = 88 77 AC AB FF EE DD CC
// => 0xCC_DD_EE_FF_AB_AC_11_22 %p1 = 0x11_22_33_44_55_66_77_88 & -1 %p2 =
// 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_FF_FF_FF_FF_FF_FF %p2.shifted = %p2 <<
// 2*8 %mask.shifted = 0x00_00_FF_FF_FF_FF_FF_FF << 2*8 =>
// 0xFF_FF_FF_FF_FF_FF_00_00 %reverse.mask.shifted = 0xFF_FF %p1.masked = %p1
// & %reverse.mask.shifted %retval = %p2.shifted | %p1.masked
//
// overwriting example WITH DIFFERENT TYPES
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 3
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33
// 22 [7] 11 [8] store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66
// [3] DD CC BB AA [7] 11 [8] %x = load i64, ptr %m1                       =>
// [0] 88 77 66 [3] DD CC BB AA [7] 11 [8] now: %x=[0] 88 77 66 [3] DD CC BB
// AA [7] 11 [8] => 0x11_AA_BB_CC_DD_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88
// & -1 %p2 = 0xAA_BB_CC_DD & 0xFF_FF_FF_FF %p2.shifted = %p2 << 1*8 =>
// 0xAA_BB_CC_DD << 8 => 0x_AA_BB_CC_DD_00 %mask.shifted = 0xFF_FF_FF_FF <<
// 1*8
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
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33
// [6] 22 11 [8] store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66
// [3] 55 44 33 [6] DD CC [8] BB AA [10] %x = load i64, ptr %m1 => [0] 88 77
// 66 [3] 55 44 33 [6] DD CC [8] BB AA [10] now: %x=[0] 88 77 66 [3] 55 44 33
// [6] DD CC [8] => 0xCC_DD_33_44_55_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88
// & -1 %p2 = 0xAA_BB_CC_DD & 0x00_00_FF_FF %p2.shifted = %p2 << 6*8 =>
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
// CC BB AA [11] 55 44 33 22 11 [16] %x = load i64, ptr %m1 => [7] DD [8] CC
// BB AA [11] 55 44 33 22 11 [16] now: %x=[7] DD [8] CC BB AA [11] 55 44 33 22
// 11 [16] => 0xCC_DD_33_44_55_66_77_88 %p1 = 0x11_22_33_44_55_66_77_88 & -1
// %p2 = 0xAA_BB_CC_DD & 0xFF_FF_FF_00 (0xFF ^ -1) %p2.shifted = %p2 << 1*8 =>
// 0xAA_BB_CC_00 >> 8 => 0xAA_BB_CC => 0x00_00_00_00_00_AA_BB_CC %mask.shifted
// = 0xFF_FF_FF_00 >> 1*8     => 0xFF_FF_FF %reverse.mask.shifted =
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