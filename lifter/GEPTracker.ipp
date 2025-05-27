#pragma once

#include "GEPTracker.h"
#include "MemoryPolicy.hpp"
#include "OperandUtils.ipp"
#include "lifterClass.hpp"
#include "utils.h"
#include <llvm/Transforms/Utils/SCCPSolver.h>
#include <magic_enum/magic_enum.hpp>

using namespace llvm;

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::addValueReference(Value* value,
                                                            uint64_t address) {
  unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
  for (unsigned i = 0; i < valueSizeInBytes; i++) {
    printvalue2(address + i);
    buffer[address + i] = ValueByteReference(value, i);
    printvalue(value);
    printvalue2((uint64_t)address + i);
  }
}

// takes direct address, not gep pointer

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::createMemcpy(Value* src, Value* dest,
                                                       Value* size) {
  if (!isa<ConstantInt>(src) || !isa<ConstantInt>(dest) ||
      !isa<ConstantInt>(size)) {
    printvalue(src);
    printvalue(dest);
    printvalue(size);
    return;
  }

  auto destCI = cast<ConstantInt>(dest);
  auto srcCI = cast<ConstantInt>(src);
  auto sizeCI = cast<ConstantInt>(size);

  auto C_src = srcCI->getZExtValue();
  auto C_dest = destCI->getZExtValue();
  auto C_size = sizeCI->getZExtValue();
  printvalue2(C_size);

  // check memory policy for source and destination
  if (memoryPolicy.isSymbolic(C_src) || memoryPolicy.isSymbolic(C_dest)) {
    // Handle symbolic memory copy
    // TODO: Implement symbolic memcpy
    return;
  }

  for (int i = 0; i < C_size; i++) {
    if (!buffer.contains(C_src + i)) {
      printvalue2(C_src + i);
      printvalue2(C_dest + i);

      buffer[C_dest + i] = ValueByteReference();
      // Handle missing source data
      continue;
    }
    buffer[C_dest + i] = buffer[C_src + i];
  }
}
// instead of passing a LazyValue, lazily load it.

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::retrieveCombinedValue(
    uint64_t startAddress, uint8_t byteCount, LazyValue orgLoad) {
  printvalue2(startAddress);

  if (memoryPolicy.isRangeFullyCovered(startAddress, startAddress + byteCount,
                                       MemoryAccessMode::SYMBOLIC)) {
    // early exit: range is fully symbolic
    return orgLoad.get();
  }

  LLVMContext& context = builder->getContext();
  if (byteCount == 0) {
    return nullptr;
  }

  // bool contiguous = true;
  SmallVector<ValueByteReferenceRange, 64>
      values; // we can just create an array here
  auto lastAccessMode = memoryPolicy.getAccessMode(startAddress);
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
    bool isLastReference = !isEmpty && values.back().isRef;
    // this needs serious refactoring
    auto currentAccessMode = memoryPolicy.getAccessMode(currentAddress);
    printvalue2(magic_enum::enum_name(currentAccessMode));
    printvalue2(magic_enum::enum_name(lastAccessMode));
    printvalue2(currentAddress);

    if (isEmpty ||
        (isLastReference && isDifferentReferenceOrDiscontinuousOffset(
                                values.back(), currentAddress) ||
         currentAccessMode != lastAccessMode)) {
      if (buffer.contains(currentAddress) &&
          currentAccessMode != MemoryAccessMode::SYMBOLIC) {
        values.push_back(
            ValueByteReferenceRange(buffer[currentAddress], i, i + 1));
      } else {
        printvalue2(currentAddress);
        values.push_back(ValueByteReferenceRange(currentAddress, i, i + 1));
      }
    } else {
      ++values.back().end;
    }
    lastAccessMode = memoryPolicy.getAccessMode(startAddress);
  }

  Value* result = ConstantInt::get(Type::getIntNTy(context, byteCount * 8), 0);

  int m = 0;
  for (auto v : values) {
    Value* byteValue = nullptr;
    uint8_t bytesize = v.end - v.start;

    uint64_t mem_value;
    printvalue2(v.isRef);

    auto read_mem = file.readMemory(v.memoryAddress, bytesize, mem_value);
    printvalue2(read_mem);
    printvalue2(mem_value);
    if (!v.isRef && memoryPolicy.isSymbolic(v.memoryAddress)) {
      byteValue = extractBytes(orgLoad.get(), m, m + bytesize);
    } else if (v.isRef) {
      byteValue = extractBytes(v.ref.value, v.ref.byteOffset,
                               v.ref.byteOffset + bytesize);
    } else if (!v.isRef &&
               file.readMemory(v.memoryAddress, bytesize, mem_value)) {

      byteValue = builder->getIntN(bytesize * 8, mem_value);
    } else if (!v.isRef) {

      byteValue = extractBytes(orgLoad.get(), m, m + bytesize);
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
  printvalue(result);
  return result;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::extractBytes(Value* value,
                                                         uint8_t startOffset,
                                                         uint8_t endOffset) {
  LLVMContext& context = builder->getContext();

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

  Value* truncatedValue = createZExtOrTruncFolder(
      shiftedValue, Type::getIntNTy(context, byteCount * 8));
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

MERGEN_LIFTER_DEFINITION_TEMPLATES(isPaged)::isValuePaged(Value* address,
                                                          Instruction* ctxI) {
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

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::pagedCheck(Value* address,
                                                     Instruction* ctxI) {
  isPaged paged = isValuePaged(address, ctxI);

  switch (paged) {
  case MEMORY_NOT_PAGED: {

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

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::loadMemoryOp(Value* ptr) {
  if (!isa<GetElementPtrInst>(ptr))
    return;

  auto gepInst = cast<GetElementPtrInst>(ptr);
  auto gepPtr = gepInst->getPointerOperand();
  if (gepPtr != memoryAlloc)
    return;

  auto gepOffset = gepInst->getOperand(1);

  pagedCheck(gepOffset, dyn_cast<Instruction>(ptr));
  return;
}

// rename func name to indicate its only for store
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::insertMemoryOp(StoreInst* inst) {
  memInfos.push_back(inst);

  auto ptr = inst->getPointerOperand();
  if (!isa<GetElementPtrInst>(ptr))
    return;

  auto gepInst = cast<GetElementPtrInst>(ptr);
  auto gepPtr = gepInst->getPointerOperand();
  if (gepPtr != memoryAlloc)
    return;

  auto gepOffset = gepInst->getOperand(1);

  pagedCheck(gepOffset, inst);

  if (!isa<ConstantInt>(gepOffset)) {
    printvalue(gepOffset);
    if (auto conditional_offset = dyn_cast<SelectInst>(gepOffset)) {
      printvalue(conditional_offset->getFalseValue());
      printvalue(conditional_offset->getCondition());
      if (auto truev =
              dyn_cast<ConstantInt>(conditional_offset->getTrueValue())) {
        auto newinst = createSelectFolder(
            conditional_offset->getCondition(), inst->getValueOperand(),
            retrieveCombinedValue(
                truev->getZExtValue(),
                inst->getValueOperand()->getType()->getIntegerBitWidth() / 8,
                nullptr)); // how tf does this even compile
        addValueReference(newinst, truev->getZExtValue());
      }
      if (auto falsev =
              dyn_cast<ConstantInt>(conditional_offset->getFalseValue())) {
        auto newinst = createSelectFolder(
            conditional_offset->getCondition(),
            retrieveCombinedValue(
                falsev->getZExtValue(),
                inst->getValueOperand()->getType()->getIntegerBitWidth() / 8,
                nullptr),
            inst->getValueOperand());
        addValueReference(newinst, falsev->getZExtValue());
      }
    }
    return;
  }

  auto gepOffsetCI = cast<ConstantInt>(gepOffset);

  addValueReference(inst->getValueOperand(), gepOffsetCI->getZExtValue());
  // BinaryOperations::WriteTo(gepOffsetCI->getZExtValue());
}

inline bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2,
                     uint64_t size2) {
  return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
}

uint64_t createmask(uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) {

  auto start_overlap = std::max(a1, b1);
  auto end_overlap = std::min(a2, b2);
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
    return std::hash<llvm::Value*>{}(pair.first) ^
           std::hash<int>{}(pair.second);
  }
};

void removeDuplicateOffsets(std::vector<Instruction*>& vec) {
  if (vec.empty())
    return;

  std::unordered_map<std::pair<Value*, int>, Instruction*, PairHash>
      latestOffsets;
  std::vector<Instruction*> uniqueInstructions;
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
    auto pair = std::make_pair(offset, size);

    if (latestOffsets.emplace(pair, *it).second) {
      uniqueInstructions.push_back(*it);
    }
  }

  vec.assign(uniqueInstructions.rbegin(), uniqueInstructions.rend());
}

int aea = 10;

using pvalueset = std::set<APInt, APIntComparator>;
MERGEN_LIFTER_DEFINITION_TEMPLATES(pvalueset)::getPossibleValues(
    const llvm::KnownBits& known, unsigned max_unknown) {

  if ((max_unknown == 0) || (max_unknown >= 4)) {

    debugging::doIfDebug([&]() {
      std::string Filename = "output_too_many_unk.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
    });
    printvalueforce2(max_unknown);
    UNREACHABLE("There is a very huge chance that this shouldnt happen");
  }
  llvm::APInt base = known.One;
  llvm::APInt unknowns = ~(known.Zero | known.One);
  unsigned numBits = known.getBitWidth();

  std::set<APInt, APIntComparator> values;

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

MERGEN_LIFTER_DEFINITION_TEMPLATES(pvalueset)::computePossibleValues(
    Value* V, uint8_t Depth) {
  printvalue2(Depth);
  if (Depth > 16) {
    debugging::doIfDebug([&]() {
      std::string Filename = "output_depth_exceeded.ll";
      std::error_code EC;
      raw_fd_ostream OS(Filename, EC);
      builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
    });
    UNREACHABLE("Depth exceeded");
  }
  std::set<APInt, APIntComparator> res;
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

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::solveLoad(LazyValue load,
                                                      Value* ptr,
                                                      uint8_t size) {

  const Value* loadPtr = ptr;

  auto cloadsize = size / 8;
  auto loadPtrGEP = cast<GetElementPtrInst>(loadPtr);
  auto loadPointer = loadPtrGEP->getPointerOperand();
  Value* loadOffset = loadPtrGEP->getOperand(1);

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
  }

  return nullptr;
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
// 0x11_22_33_44_55_66_77_88 & 0x00_00_FF_FF_FF_FF_FF =>
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