#include "includes.h"
#include "OperandUtils.h"


// https://github.com/llvm/llvm-project/blob/3da065896b1b59fd8291958e8d13f4a942d51214/llvm/lib/Transforms/Scalar/EarlyCSE.cpp#L1552C5-L1552C21

using memoryValue = Value*;
using idxValue = Value*;
using ptrValue = Value*;

using memoryInfo = tuple<ptrValue, idxValue, memoryValue, bool>;

// replace it with https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Analysis/MemoryLocation.h#L228 but I think this might be better after build, not while building
class ValueByteReference2 {
public:
    Value* value;
    short byteOffset;

    ValueByteReference2(Value* val, short offset) : value(val), byteOffset(offset) {}
};

class lifterMemoryBuffer2 {
public:
    std::vector<ValueByteReference2*> buffer;

    lifterMemoryBuffer2() : buffer(STACKP_VALUE, nullptr) {}

    ~lifterMemoryBuffer2() {

        for (auto* ref : buffer) {
            delete ref;
        }
    }

    void addValueReference(Value* value, unsigned address) {
        unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
        for (unsigned i = 0; i < valueSizeInBytes; i++) {

            delete buffer[address + i];

            buffer[address + i] = new ValueByteReference2(value, i);
        }
    }

    Value* retrieveCombinedValue(IRBuilder<>& builder, unsigned startAddress, unsigned byteCount) {
        LLVMContext& context = builder.getContext();
        if (byteCount == 0) return nullptr;


        Value* firstSource = nullptr;
        bool contiguous = true;

        for (unsigned i = 0; i < byteCount && contiguous; ++i) {
            unsigned currentAddress = startAddress + i;
            if (currentAddress >= buffer.size() || buffer[currentAddress] == nullptr) {
                contiguous = false;
                break;
            }
            if (i == 0) {
                firstSource = buffer[currentAddress]->value;
            }
            else if (buffer[currentAddress]->value != firstSource || buffer[currentAddress]->byteOffset != i) {
                contiguous = false;
            }
        }


        if (contiguous && firstSource != nullptr && byteCount == firstSource->getType()->getIntegerBitWidth() / 8) {
            return firstSource;
        }

        // supposed to return 0 if never used, wtf?
        if (firstSource == nullptr) {
            return ConstantInt::get(Type::getIntNTy(context, byteCount), 0);
        }

        Value* result = nullptr;

        for (unsigned i = 0; i < byteCount; i++) {
            unsigned currentAddress = startAddress + i;
            if (currentAddress < buffer.size() && buffer[currentAddress] != nullptr) {
                auto* ref = buffer[currentAddress];
                Value* byteValue = extractByte(builder, ref->value, ref->byteOffset);
                if (!result) {
                    result = createZExtFolder(builder, byteValue, Type::getIntNTy(builder.getContext(), byteCount * 8));
                }
                else {
                    Value* shiftedByteValue = createShlFolder(builder, createZExtFolder(builder, byteValue, Type::getIntNTy(builder.getContext(), byteCount * 8)), APInt(byteCount * 8, i * 8));
                    result = createAddFolder(builder, result, shiftedByteValue, "extractbytesthing");
                }
            }

        }
        return result;
    }

private:
    Value* extractByte(IRBuilder<>& builder, Value* value, unsigned byteOffset) {

        if (!value) {
            return ConstantInt::get(Type::getInt8Ty(builder.getContext()), 0);
        }
        unsigned shiftAmount = byteOffset * 8;
        Value* shiftedValue = createLShrFolder(builder, value, APInt(value->getType()->getIntegerBitWidth(), shiftAmount), "extractbyte");
        //printvalueforce(shiftedValue)
        return createTruncFolder(builder, shiftedValue, Type::getInt8Ty(builder.getContext()));
    }
};


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


    // sections
    bool readMemory(uintptr_t addr, unsigned byteSize, APInt& value) {


        uintptr_t mappedAddr = address_to_mapped_address(file_base_g, addr);
        uintptr_t tempValue;

        if (mappedAddr > 0) {
            std::memcpy(&tempValue, reinterpret_cast<const void*>(data_g + mappedAddr), byteSize);

            APInt readValue(byteSize * 8, tempValue);
            value = readValue;
            return 1;
        }

        return 0;
    }

    // TODO
    // 1- if writes into execute section, flag that address, if we execute that address then do fancy stuff to figure out what we wrote so we know what we will be executing
    void writeMemory();

};


// do some cleanup
namespace GEPStoreTracker {
    DominatorTree *DT;

    // only push stores to here
    vector<memoryInfo> memInfos;

    BasicBlock* lastBB = nullptr;

    void initDomTree(Function& F) {
        DT = new DominatorTree(F);
    }
    DominatorTree* getDomTree() {
        return DT;
    }

    void updateDomTree(Function& F) {
        // doesnt make a much difference, but good to have
        auto getLastBB = &(F.back());
        if (getLastBB != lastBB)
            DT->recalculate(F);
        lastBB = getLastBB;
    }

    // rename
    vector<Instruction*> memInfos2;
    void insertMemoryOp(Instruction* inst) {
        memInfos2.push_back(inst);
    }    
    
    bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2, uint64_t size2) {
        return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
    }


    uint64_t createmask(unsigned long a1, unsigned long a2, unsigned long b1, unsigned long b2) {

        auto start_overlap = max(a1, b1);
        auto end_overlap = min(a2, b2);
        long diffStart = a1 - b1;

        printvalue2(start_overlap)
        printvalue2(end_overlap)
        // If there is no overlap
        if (start_overlap > end_overlap) 
            return 0; 

        auto num_bytes = end_overlap - start_overlap;
        // mask =>  
        unsigned long long mask = 0xffffffffffffffff >> 64-(num_bytes*8); // adjust mask for bytesize
        printvalue2(diffStart)
        if (diffStart <= 0)
            return mask;

            
        auto diffShift = abs(diffStart);

        printvalue2(mask)
        mask <<= (diffShift)*8; // get the shifted mask
        printvalue2(mask)

        mask ^=  -(diffStart < 0); // if diff was -, get the negative of mask
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
        unordered_set<pair<Value*, int> , PairHash> latestOffsets;

        vector<Instruction*> uniqueInstructions;

        auto it = vec.rbegin(); // Start from the beginning of the reversed vector
        while (it != vec.rend()) {
            auto inst = cast<StoreInst>(*it);
            auto GEPval = inst->getPointerOperand();
            auto valOp = inst->getValueOperand();
            int size = valOp->getType()->getIntegerBitWidth();
            auto GEPInst = cast<GetElementPtrInst>(GEPval);
            auto offset = GEPInst->getOperand(1);
            auto pair = make_pair(offset, size);

            if (latestOffsets.find(pair) == latestOffsets.end()) {
                // If the pair (offset, size) is not encountered before, add it to the unique vector
                uniqueInstructions.push_back(*it);

                // Update the latest occurrence of the pair
                latestOffsets.insert(pair);
            }

            ++it;
        }

        // Replace the original vector with the unique vector
        vec = vector<Instruction*>(uniqueInstructions.rbegin(), uniqueInstructions.rend());
    }

    void removeFutureInsts(vector<Instruction*>& vec, LoadInst* load) {
        // profile binary search first: with binary search, approx time: 1: ~4 0: ~8
        // w/o 1: 5213221 0 : 10792287

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

        if (!buildTime)
            GEPStoreTracker::updateDomTree(*F);


        // replace this
        auto LoadMemLoc = MemoryLocation::get(load);

        const Value* loadPtr = LoadMemLoc.Ptr;
        LocationSize loadsize = LoadMemLoc.Size;

        auto cloadsize = loadsize.getValue();
        //printvalueforce2(cloadsize);
        
        auto loadPtrGEP = cast<GetElementPtrInst>(loadPtr);

        auto loadPointer = loadPtrGEP->getPointerOperand();
        auto loadOffset = loadPtrGEP->getOperand(1);


        // create a new vector with only leave what we care about
        vector<Instruction*> clearedMemInfos;

        clearedMemInfos = memInfos2;

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
            //auto MemLoc = MemoryLocation::get(inst);

            StoreInst* storeInst = cast<StoreInst>(inst);
            auto memLocationValue = storeInst->getPointerOperand();

            // shouldnt happen anyways
            /*
            if (!isa<GetElementPtrInst>(memLocationValue))
                continue;
            */
            auto memLocationGEP = cast<GetElementPtrInst>(memLocationValue);

            auto pointer = memLocationGEP->getOperand(0);
            auto offset = memLocationGEP->getOperand(1);

            
            if (pointer != loadPointer)
                break;


            // find a way to compare with unk values, we are also interested when offset in unk ( should be a rare case ) 
            if (!isa<ConstantInt>(offset) || !isa<ConstantInt>(loadOffset))
                continue;

            auto memOffsetValue = cast<ConstantInt>(offset)->getZExtValue();
            auto loadOffsetValue = cast<ConstantInt>(loadOffset)->getZExtValue();

            long diff = memOffsetValue - loadOffsetValue;


            // this is bytesize, not bitsize
            auto storeBitSize = storeInst->getValueOperand()->getType()->getIntegerBitWidth() / 8;
            //outs() << " \nstoreBitSize: " << storeBYTESize << " \n normal size: " << storeInst->getValueOperand()->getType()->getIntegerBitWidth() << "\n"; outs().flush();
            //if (std::max(loadOffsetValue, memOffsetValue) < std::min(loadOffsetValue + cloadsize, memOffsetValue + MemLoc.Size.getValue() )) {
            if (overlaps(loadOffsetValue, cloadsize, memOffsetValue, storeBitSize)) {
                
                printvalueforce2(diff)
                printvalueforce2(memOffsetValue)
                printvalueforce2(loadOffsetValue)
                printvalueforce2(storeBitSize)

                    auto storedInst = inst->getOperand(0);
                if (!retval)
                    retval = ConstantInt::get(load->getType(), 0);
               
               
                long sizeExceeded = max( (int)( (memOffsetValue+ storeBitSize) -(loadOffsetValue + cloadsize)) , 0);
                Value* mask = ConstantInt::get(storedInst->getType(), createmask(loadOffsetValue, loadOffsetValue + cloadsize, memOffsetValue, memOffsetValue + storeBitSize));

                printvalueforce(mask)
                
                auto bb = inst->getParent();
                IRBuilder<> builder(load);
                // we dont have to calculate knownbits if its a constant
                auto maskedinst = createAndFolder(builder, storedInst, mask, inst->getName() + ".maskedinst");

                printvalueforce(storedInst);
                printvalueforce(mask);
                printvalueforce(maskedinst);
                if (maskedinst->getType()->getScalarSizeInBits() < retval->getType()->getScalarSizeInBits()) 
                    maskedinst = builder.CreateZExt(maskedinst, retval->getType());

                if (mask->getType()->getScalarSizeInBits() < retval->getType()->getScalarSizeInBits()) 
                    mask = builder.CreateZExt(mask, retval->getType());
                
                printvalueforce(maskedinst);
                printvalue2(diff);
                // move the mask?
                if (diff > 0) {
                    maskedinst = createShlFolder(builder, maskedinst, (diff) * 8);
                    mask = createShlFolder(builder, mask, (diff) * 8);
                }
                else if (diff < 0) {
                    maskedinst = createLShrFolder(builder, maskedinst, -(diff) * 8);
                    mask = createLShrFolder(builder, mask, -(diff) * 8);
                }
                // maskedinst = maskedinst
                // maskedinst = 0x4433221100000000
                printvalueforce(maskedinst);
                maskedinst = builder.CreateZExtOrTrunc(maskedinst, retval->getType());
                printvalueforce(maskedinst);
                

                printvalueforce(mask);

                // clear mask from retval so we can merge
                // this will be a NOT operation for sure
                // 
                 // overhead
                auto reverseMask = builder.CreateNot(mask);
                
                printvalueforce(reverseMask);

                // overhead
                auto cleared_retval = createAndFolder(builder,retval, reverseMask, retval->getName() + ".cleared");
                // cleared_retval = 0 & 0; clear retval
                // cleared_retval = retval & 0xff_ff_ff_ff_00_00_00_00

                retval = createOrFolder(builder, cleared_retval, maskedinst, cleared_retval->getName() + ".merged");
                //retval = builder.CreateTrunc(retval, load->getType());
                printvalueforce(cleared_retval);
                printvalueforce(maskedinst);
                // retval = cleared_retval | maskedinst =|= 0 | 0x1122334455667788
                // retval = cleared_retval | maskedinst =|= 0x55667788 | 0x4433221100000000

                if (retval)
                    if (retval->getType()->getScalarSizeInBits() > load->getType()->getScalarSizeInBits())
                        retval = builder.CreateTrunc(retval, load->getType());

                printvalueforce(inst);
                auto retvalload = retval;
                printvalueforce(cleared_retval);
                printvalueforce(retvalload);
                //string next_line = "------------------------------";
                printvalue2(next_line)
            }

        }
        return retval;
    }

    // remove
    void insertInfo(ptrValue pv, idxValue av, memoryValue mv, bool isStore) {
        memInfos.push_back(make_tuple(pv, av, mv, isStore));
    }

    // remove
    memoryValue getValueAt(IRBuilder<>& builder, ptrValue pv, idxValue iv, unsigned int byteCount) {


        if (!isa<ConstantInt>(iv))
            return nullptr;

        // i really want to replace this buffer
        lifterMemoryBuffer2 tempBuffer;
        // only care about %memory values for now 


        // replace queue with vector maybe?

        for (memoryInfo info : memInfos) {

            ptrValue t_ptr = get<0>(info);

            idxValue t_idx = get<1>(info);

            memoryValue t_mem = get<2>(info);
            
            bool isStore = get<3>(info);
            
            // printvalueforce(t_ptr)
                // printvalueforce(t_idx)
            
            /*if (t_mem) {
                printvalueforce(t_mem)
            }
            */
            
            if (t_ptr == pv && !isa<ConstantInt>(t_idx) && !isStore) { // if we hit the load, return? 
                break;
            }

            //printvalueforce2(isStore)
            if (!isStore) // if not store, no reason to insert it to our buffer
                continue;

            if (!isa<ConstantInt>(t_idx))
                continue;

            ConstantInt* t_CI = cast<ConstantInt>(t_idx);
            tempBuffer.addValueReference(t_mem, t_CI->getZExtValue() );


        }

        //printvalueforce(pv)
        //printvalueforce(iv)

        // this will create a temporary buffer, write all the values until we hit addressValue then retrieve the value from there
        // multiple values should not be a problem since the order doesnt matter 


        ConstantInt* CI = cast<ConstantInt>(iv);

        Value* retvalue = tempBuffer.retrieveCombinedValue(builder,CI->getZExtValue(), byteCount );

        //printvalueforce(retvalue)

        return retvalue;

    }

};



// some stuff about memory
// partial load example
// 
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 4
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 55 [4] 44 33 22 11 [8]
// store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m3 => [0] 88 77 66 55 [4] 44 33 22 11 [8] AC AB FF EE [12] DD CC BB AA [16]
// %x = load i64, ptr %m2                       => [0] 88 77 66 55 [4] 44 33 22 11 [8] AC AB FF EE [12] DD CC BB AA [16]
// now:                                         %x = 44 33 22 11 AC AB FF EE => 0xEE_FF_AB_AC_11_22_33_44
// %p1 = 0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_FF_00_00_00_00
// %p2 = 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_00_00_FF_FF_FF_FF
// %p3 = 0
// %p1.shift = %p1 >> 4(diff)*8
// %p2.shift = %p2 << 4(diff)*8
// %p4 = %p1.shift | %p2.shift
// 
// overwriting example
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 2
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 [2] 66 55 [4] 44 33 22 11 [8]
// store i64 0xAA_BB_CC_DD_EE_FF_AB_AC, ptr %m2 => [0] 88 77 [2] AC AB [4] FF EE DD CC [8] BB AA [10]
// %x = load i64, ptr %m1                       => [0] 88 77 [2] AC AB [4] FF EE DD CC [8] BB AA [10]
// now:                                         %x = 88 77 AC AB FF EE DD CC => 0xCC_DD_EE_FF_AB_AC_11_22
// %p1 = 0x11_22_33_44_55_66_77_88 & -1
// %p2 = 0xAA_BB_CC_DD_EE_FF_AB_AC & 0x00_00_FF_FF_FF_FF_FF_FF
// %p2.shifted = %p2 << 2*8
// %mask.shifted = 0x00_00_FF_FF_FF_FF_FF_FF << 2*8 => 0xFF_FF_FF_FF_FF_FF_00_00
// %reverse.mask.shifted = 0xFF_FF 
// %p1.masked = %p1 & %reverse.mask.shifted
// %retval = %p2.shifted | %p1.masked
//
// overwriting example WITH DIFFERENT TYPES
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 3
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33 22 [7] 11 [8]
// store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66 [3] DD CC BB AA [7] 11 [8]
// %x = load i64, ptr %m1                       => [0] 88 77 66 [3] DD CC BB AA [7] 11 [8]
// now:                                         %x=[0] 88 77 66 [3] DD CC BB AA [7] 11 [8] => 0x11_AA_BB_CC_DD_66_77_88
// %p1 = 0x11_22_33_44_55_66_77_88 & -1
// %p2 = 0xAA_BB_CC_DD & 0xFF_FF_FF_FF 
// %p2.shifted = %p2 << 1*8                 =>  0xAA_BB_CC_DD << 8 => 0x_AA_BB_CC_DD_00
// %mask.shifted = 0xFF_FF_FF_FF << 1*8     => 0x00_00_00_FF_FF_FF_FF_00
// %reverse.mask.shifted = 0xFF_FF_FF_00_00_00_00_FF 
// %p1.masked = %p1 & %reverse.mask.shifted =>  0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_00_00_00_00_FF => 0x11_22_33_00_00_00_00_88
// %retval = %p2.shifted | %p1.masked       =>  0x11_22_33_00_00_00_00_88 | 0x00_00_00_AA_BB_CC_DD_00 => 0x11_22_33_AA_BB_CC_DD_88
// 
// PARTIAL overwriting example WITH DIFFERENT TYPES v1
//
//
//
// %m1 = getelementptr i8, %memory, i64 0
// %m2 = getelementptr i8, %memory, i64 6
// %m3 = getelementptr i8, %memory, i64 8
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [0] 88 77 66 [3] 55 44 33 [6] 22 11 [8] 
// store i32 0xAA_BB_CC_DD, ptr %m2             => [0] 88 77 66 [3] 55 44 33 [6] DD CC [8] BB AA [10]
// %x = load i64, ptr %m1                       => [0] 88 77 66 [3] 55 44 33 [6] DD CC [8] BB AA [10]
// now:                                         %x=[0] 88 77 66 [3] 55 44 33 [6] DD CC [8] => 0xCC_DD_33_44_55_66_77_88
// %p1 = 0x11_22_33_44_55_66_77_88 & -1
// %p2 = 0xAA_BB_CC_DD & 0x00_00_FF_FF 
// %p2.shifted = %p2 << 6*8                 =>  0xCC_DD << 48 => 0xCC_DD_00_00_00_00_00_00
// %mask.shifted = 0xFF_FF_FF_FF << 6*8     => 0xFF_FF_00_00_00_00_00_00
// %reverse.mask.shifted = 0x00_00_FF_FF_FF_FF_FF_FF
// %p1.masked = %p1 & %reverse.mask.shifted =>  0x11_22_33_44_55_66_77_88 & 0x00_00_FF_FF_FF_FF_FF_FF => 0x00_00_33_44_55_66_77_88
// %retval = %p2.shifted | %p1.masked       =>  0x00_00_33_44_55_66_77_88 | 0xCC_DD_00_00_00_00_00_00 => 0xCC_DD_33_44_55_66_77_88
//
// 
// PARTIAL overwriting example WITH DIFFERENT TYPES v2
//
//
//
// %m1 = getelementptr i8, %memory, i64 8
// %m2 = getelementptr i8, %memory, i64 7
// %m3 = getelementptr i8, %memory, i64 16
// store i64 0x11_22_33_44_55_66_77_88, ptr %m1 => [7] ?? [8] 88 77 66 [11] 55 44 33 22 11 [16] 
// store i32 0xAA_BB_CC_DD, ptr %m2             => [7] DD [8] CC BB AA [11] 55 44 33 22 11 [16]
// %x = load i64, ptr %m1                       => [7] DD [8] CC BB AA [11] 55 44 33 22 11 [16] 
// now:                                         %x=[7] DD [8] CC BB AA [11] 55 44 33 22 11 [16] => 0xCC_DD_33_44_55_66_77_88
// %p1 = 0x11_22_33_44_55_66_77_88 & -1
// %p2 = 0xAA_BB_CC_DD & 0xFF_FF_FF_00 (0xFF ^ -1)
// %p2.shifted = %p2 << 1*8                 =>  0xAA_BB_CC_00 >> 8 => 0xAA_BB_CC => 0x00_00_00_00_00_AA_BB_CC
// %mask.shifted = 0xFF_FF_FF_00 >> 1*8     => 0xFF_FF_FF
// %reverse.mask.shifted = 0xFF_FF_FF_FF_FF_00_00_00
// %p1.masked = %p1 & %reverse.mask.shifted =>  0x11_22_33_44_55_66_77_88 & 0xFF_FF_FF_FF_FF_00_00_00 => 0x11_22_33_44_55_00_00_00
// %retval = %p2.shifted | %p1.masked       =>  0x11_22_33_44_55_00_00_00 | 0xAA_BB_CC                => 0x11_22_33_44_55_AA_BB_CC
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