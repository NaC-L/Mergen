#include "GEPTracker.h"
#include "OperandUtils.h"
#include "includes.h"

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

    const char* getName(unsigned long long offset) {
        auto dosHeader = (win::dos_header_t*)file_base_g;
        auto ntHeaders = (win::nt_headers_x64_t*)((uint8_t*)file_base_g +
                                                  dosHeader->e_lfanew);
        auto rvaOffset = FileHelper::RvaToFileOffset(ntHeaders, offset);
        return (const char*)file_base_g + rvaOffset;
    }

    unordered_set<uint64_t> MemWrites;

    bool isWrittenTo(uint64_t addr) {
        return MemWrites.find(addr) != MemWrites.end();
    }
    void WriteTo(uint64_t addr) { MemWrites.insert(addr); }

    // sections
    bool readMemory(uintptr_t addr, unsigned byteSize, APInt& value) {

        uintptr_t mappedAddr =
            FileHelper::address_to_mapped_address(file_base_g, addr);
        uintptr_t tempValue;

        if (mappedAddr > 0) {
            std::memcpy(&tempValue,
                        reinterpret_cast<const void*>(data_g + mappedAddr),
                        byteSize);

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
    short byteOffset;

    ValueByteReference(Instruction* inst, Value* val, short offset)
        : storeInst(inst), value(val), byteOffset(offset) {}
};

class lifterMemoryBuffer {
  public:
    std::vector<ValueByteReference*> buffer;

    lifterMemoryBuffer() : buffer(STACKP_VALUE, nullptr) {}
    lifterMemoryBuffer(unsigned long long bufferSize)
        : buffer(bufferSize, nullptr) {}

    ~lifterMemoryBuffer() {

        for (auto* ref : buffer) {
            delete ref;
        }
    }

    void addValueReference(Instruction* inst, Value* value, uint64_t address) {
        unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
        for (unsigned i = 0; i < valueSizeInBytes; i++) {

            delete buffer[address + i];
            BinaryOperations::WriteTo(address + i);
            printvalue2(address + i);
            buffer[address + i] = new ValueByteReference(inst, value, i);
            printvalue(value);
            printvalue2((unsigned long)address + i);
        }
    }

    void updateValueReference(Instruction* inst, Value* value,
                              uint64_t address) {
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

            printvalue2((unsigned long)address + i);
        }
    }

    // goal : get rid of excess operations
    /*
    how?
    create a temp var for contiguous values

    */
    Value* retrieveCombinedValue(IRBuilder<>& builder, unsigned startAddress,
                                 unsigned byteCount) {
        LLVMContext& context = builder.getContext();
        if (byteCount == 0) {

            return nullptr;
        }

        Value* firstSource = nullptr;
        bool contiguous = true;

        // modify this loop
        for (unsigned i = 0; i < byteCount && contiguous; ++i) {
            unsigned currentAddress = startAddress + i;
            if (currentAddress >= buffer.size() ||
                buffer[currentAddress] == nullptr) {
                contiguous = false;
                printvalue2(contiguous);
                break;
            }
            if (i == 0) {
                firstSource = buffer[currentAddress]->value;
            }
            if (buffer[currentAddress]->value != firstSource ||
                buffer[currentAddress]->byteOffset != i) {
                contiguous = false;
                printvalue2(contiguous);
            }
        }

        if (contiguous && firstSource != nullptr &&
            byteCount <= firstSource->getType()->getIntegerBitWidth() / 8) {
            return builder.CreateTrunc(firstSource,
                                       Type::getIntNTy(context, byteCount * 8));
        }

        if (firstSource == nullptr) {
            return ConstantInt::get(Type::getIntNTy(context, byteCount * 8), 0);
        }

        // when do we want to return nullptr and when do we want to return 0 ?
        Value* result =
            ConstantInt::get(Type::getIntNTy(context, byteCount * 8), 0);

        for (unsigned i = 0; i < byteCount; i++) {
            unsigned currentAddress = startAddress + i;
            if (currentAddress < buffer.size() &&
                buffer[currentAddress] != nullptr) {
                auto* ref = buffer[currentAddress];
                Value* byteValue =
                    extractByte(builder, ref->value, ref->byteOffset);

                printvalue(byteValue);
                if (!result) {
                    result = createZExtFolder(
                        builder, byteValue,
                        Type::getIntNTy(context, byteCount * 8));
                } else {
                    Value* shiftedByteValue = createShlFolder(
                        builder,
                        createZExtFolder(
                            builder, byteValue,
                            Type::getIntNTy(context, byteCount * 8)),
                        APInt(byteCount * 8, i * 8));
                    result = createOrFolder(builder, result, shiftedByteValue,
                                            "extractbytesthing");
                }
            }
        }
        printvalue(result);
        return result;
    }

  private:
    Value* extractByte(IRBuilder<>& builder, Value* value,
                       unsigned long long byteOffset) {

        if (!value) {
            return ConstantInt::get(Type::getInt8Ty(builder.getContext()), 0);
        }
        unsigned long long shiftAmount = byteOffset * 8;
        Value* shiftedValue = createLShrFolder(
            builder, value,
            APInt(value->getType()->getIntegerBitWidth(), shiftAmount),
            "extractbyte");
        printvalue2(shiftAmount);
        printvalue(shiftedValue);
        return createTruncFolder(builder, shiftedValue,
                                 Type::getInt8Ty(builder.getContext()));
    }
};

namespace SCCPSimplifier {
    std::unique_ptr<SCCPSolver> solver;
    unsigned long long lastinstcount = 0;
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

        solver =
            std::make_unique<SCCPSolver>(function->getParent()->getDataLayout(),
                                         GetTLI, function->getContext());
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
namespace GEPStoreTracker {
    DominatorTree* DT;
    BasicBlock* lastBB = nullptr;

    // Apparently this is a faster solution for runtime, but it uses more
    // memory.
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

        // have to update memInfos aswell
        // memInfos.push_back(inst);

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
        if (gepOffsetCI->getZExtValue() < VirtualStack.buffer.size()) {
            auto updatingstack = inst;
            VirtualStack.updateValueReference(inst, inst->getValueOperand(),
                                              gepOffsetCI->getZExtValue());
        }
    }

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
        if (!isa<ConstantInt>(gepOffset))
            return;

        auto gepOffsetCI = cast<ConstantInt>(gepOffset);
        if (gepOffsetCI->getZExtValue() < VirtualStack.buffer.size())
            VirtualStack.addValueReference(inst, inst->getValueOperand(),
                                           gepOffsetCI->getZExtValue());
    }

    bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2,
                  uint64_t size2) {
        return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
    }

    uint64_t createmask(unsigned long a1, unsigned long a2, unsigned long b1,
                        unsigned long b2) {

        auto start_overlap = max(a1, b1);
        auto end_overlap = min(a2, b2);
        long diffStart = a1 - b1;

        printvalue2(start_overlap) printvalue2(end_overlap)
            // If there is no overlap
            if (start_overlap > end_overlap) return 0;

        auto num_bytes = end_overlap - start_overlap;
        // mask =>
        unsigned long long mask =
            0xffffffffffffffff >>
            (64 - (num_bytes * 8)); // adjust mask for bytesize
        printvalue2(diffStart) if (diffStart <= 0) return mask;

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
        auto it = std::lower_bound(vec.begin(), vec.end(), load,
                                   [](Instruction* a, Instruction* b) {
                                       return comesBefore(a, b, *DT);
                                   });

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

                // todo: replace the condition to check if CI is in buffer where
                // buffer is not stack
                auto loadOffsetCIval = loadOffsetCI->getZExtValue();
                printvalue2(loadOffsetCIval);
                if (VirtualStack.buffer.size() > loadOffsetCIval) {
                    printvalue2(loadOffsetCIval);
                    IRBuilder<> builder(load);
                    if (auto valueExtractedFromVirtualStack =
                            VirtualStack.retrieveCombinedValue(
                                builder, loadOffsetCIval, cloadsize)) {
                        printvalue(valueExtractedFromVirtualStack);
                        return valueExtractedFromVirtualStack;
                    }
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

            unsigned long memOffsetValue =
                cast<ConstantInt>(offset)->getZExtValue();
            unsigned long loadOffsetValue =
                cast<ConstantInt>(loadOffset)->getZExtValue();

            unsigned long diff = memOffsetValue - loadOffsetValue;

            // this is bytesize, not bitsize
            unsigned long storeBitSize =
                storeInst->getValueOperand()->getType()->getIntegerBitWidth() /
                8;
            // outs() << " \nstoreBitSize: " << storeBYTESize << " \n normal
            // size: " <<
            // storeInst->getValueOperand()->getType()->getIntegerBitWidth() <<
            // "\n"; outs().flush(); if (std::max(loadOffsetValue,
            // memOffsetValue) < std::min(loadOffsetValue + cloadsize,
            // memOffsetValue + MemLoc.Size.getValue() )) {
            if (overlaps(loadOffsetValue, cloadsize, memOffsetValue,
                         storeBitSize)) {

                printvalue2(diff) printvalue2(memOffsetValue)
                    printvalue2(loadOffsetValue) printvalue2(storeBitSize)

                        auto storedInst = inst->getOperand(0);
                if (!retval)
                    retval = ConstantInt::get(load->getType(), 0);

                long sizeExceeded = max((int)((memOffsetValue + storeBitSize) -
                                              (loadOffsetValue + cloadsize)),
                                        0);
                Value* mask = ConstantInt::get(
                    storedInst->getType(),
                    createmask(loadOffsetValue, loadOffsetValue + cloadsize,
                               memOffsetValue, memOffsetValue + storeBitSize));

                printvalue(mask)

                    auto bb = inst->getParent();
                IRBuilder<> builder(load);
                // we dont have to calculate knownbits if its a constant
                auto maskedinst = createAndFolder(
                    builder, storedInst, mask, inst->getName() + ".maskedinst");

                printvalue(storedInst);
                printvalue(mask);
                printvalue(maskedinst);
                if (maskedinst->getType()->getScalarSizeInBits() <
                    retval->getType()->getScalarSizeInBits())
                    maskedinst =
                        builder.CreateZExt(maskedinst, retval->getType());

                if (mask->getType()->getScalarSizeInBits() <
                    retval->getType()->getScalarSizeInBits())
                    mask = builder.CreateZExt(mask, retval->getType());

                printvalue(maskedinst);
                printvalue2(diff);
                // move the mask?
                if (diff > 0) {
                    maskedinst =
                        createShlFolder(builder, maskedinst, (diff) * 8);
                    mask = createShlFolder(builder, mask, (diff) * 8);
                } else if (diff < 0) {
                    maskedinst = createLShrFolder(builder, maskedinst,
                                                  -(diff) * 8, "clevername");
                    mask = createLShrFolder(builder, mask, -(diff) * 8,
                                            "stupidname");
                }
                // maskedinst = maskedinst
                // maskedinst = 0x4433221100000000
                printvalue(maskedinst);
                maskedinst =
                    builder.CreateZExtOrTrunc(maskedinst, retval->getType());
                printvalue(maskedinst);

                printvalue(mask);

                // clear mask from retval so we can merge
                // this will be a NOT operation for sure
                //
                // overhead
                auto reverseMask = builder.CreateNot(mask);

                printvalue(reverseMask);

                // overhead
                auto cleared_retval = createAndFolder(
                    builder, retval,
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
                debugging::doIfDebug(
                    [&]() { cout << "-------------------\n"; });
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