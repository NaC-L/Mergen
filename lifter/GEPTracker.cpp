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



namespace GEPStoreTracker {
    DominatorTree *DT;

    // only push stores to here
    vector<memoryInfo> memInfos;


    void initDomTree(Function& F) {
        DT = new DominatorTree(F);
    }

    void updateDomTree(Function& F) {
        DT->recalculate(F);
    }

    vector<Instruction*> memInfos2;

    void insertMemoryOp(Instruction* inst) {
        // no reason to push loads anymore
        memInfos2.push_back(inst);
    }    
    
    bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2, uint64_t size2) {
        return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
    }


    uint64_t createmask(long diff, unsigned sizebits) {

        long shift = abs(diff);

        auto mask = (0xFFFFFFFFFFFFFFFFULL >> 64 - sizebits * 8) << shift * 8;

        return mask ^ -(diff > 0); // 0 or -1 if 0, noop, if -1 xor

    }


    Value* solveLoad(LoadInst* load) {
        Function* F = load->getFunction();
        

        auto LoadMemLoc = MemoryLocation::get(load);

        const Value* loadPtr = LoadMemLoc.Ptr;
        LocationSize loadsize = LoadMemLoc.Size;

        auto cloadsize = loadsize.getValue();
        //printvalueforce2(cloadsize);
        
        // shouldnt happen anyways
        if (!isa<GetElementPtrInst>(loadPtr))
            return nullptr;
        auto loadPtrGEP = cast<GetElementPtrInst>(loadPtr);

        auto loadPointer = loadPtrGEP->getPointerOperand();
        auto loadOffset = loadPtrGEP->getOperand(1);


        

        Value* retval = nullptr;

        for (auto inst : memInfos2) {

            // we are only interested in previous instructions
            
            //printvalueforce2(comesBefore(load,inst))
            if (comesBefore(load, inst, *DT)) {
                printvalue(load)
                printvalue(inst)
                break;
            }

            // we are only interested in stores
            if (!inst->mayWriteToMemory())
                continue;


            auto MemLoc = MemoryLocation::get(inst);

            auto memLocationValue = MemLoc.Ptr;

            // shouldnt happen anyways
            if (!isa<GetElementPtrInst>(memLocationValue))
                continue;
            auto memLocationGEP = cast<GetElementPtrInst>(memLocationValue);

            auto pointer = memLocationGEP->getPointerOperand();
            auto offset = memLocationGEP->getOperand(1);

            
            if (pointer != loadPointer)
                break;


            // find a way to compare with unk values, we are also interested when offset in unk ( should be a rare case ) 
            if (!isa<ConstantInt>(offset) || !isa<ConstantInt>(loadOffset))
                continue;

            auto memOffsetValue = cast<ConstantInt>(offset)->getZExtValue();
            auto loadOffsetValue = cast<ConstantInt>(loadOffset)->getZExtValue();

            long diff = memOffsetValue - loadOffsetValue;

            // say we want to access 4
            // and 0 stores A, 8 stores B
            // 0 <= 4 <= 0+SIZE  // 4 (load starting) is in 0 (first store, 0 to 8 range) 
            // 8 <= 4+SIZE <= 8+SIZE // 4+SIZE (load end) is in 8 (last store 8 to 16 range)
            //
            // what if we want to access 0
            // 0 <= 0 <= 0+SIZE // correct
            // 0 <= 0+SIZE <= 0+SIZE // correct
            //
            // now do this with variables
            // a <= c <= a+SIZE
            // b <= c+SIZE <= b+SIZE
            // simplify it to
            // 0 <= c-a <= SIZE
            // -SIZE <= c-b <= 0 
            // 
            //  ???
            //
            // what if we have more than 2 stores 
            // store 0x1234 at 0 ( 0 = 0x12, 1 = 0x34)
            // store 0x56 at 2 ( 2 = 0x56)
            // store 0x78 at 3 ( 3 = 0x78)
            /*

            */
            auto storeBitSize = MemLoc.Size.getValue();
            //if (std::max(loadOffsetValue, memOffsetValue) < std::min(loadOffsetValue + cloadsize, memOffsetValue + MemLoc.Size.getValue() )) {
            if (overlaps(loadOffsetValue, cloadsize, memOffsetValue, storeBitSize)) {
                
                printvalueforce2(diff)
                printvalueforce2(memOffsetValue)
                printvalueforce2(loadOffsetValue)

                if (!retval)
                    retval = ConstantInt::get(load->getType(), 0);

                Value* mask = ConstantInt::get(load->getType(), createmask(diff, storeBitSize));
                // diff -4 = 0xFF_FF_FF_FF_00_00_00_00
                // diff  4 = 0x00_00_00_00_FF_FF_FF_FF
                printvalueforce(mask)


                // mask inst here
                // then or with retval

                auto bb = inst->getParent();
                IRBuilder<> builder(load);


                // get negated mask and or then?
                auto maskedinst = createAndFolder(builder, builder.CreateZExtOrTrunc(inst->getOperand(0), retval->getType()) , mask, inst->getName() + ".maskedinst");

                printvalueforce(maskedinst);
                // move the mask?
                if (diff > 0) {
                    maskedinst = createShlFolder(builder, maskedinst, diff * 8);
                    mask = createShlFolder(builder, mask, diff * 8);

                }
                else {
                    maskedinst = createLShrFolder(builder, maskedinst, -diff * 8);
                    mask = createLShrFolder(builder, mask, -diff * 8);
                }
                printvalueforce(maskedinst);
                
                // clear mask
                auto cleared_retval = createAndFolder(builder,retval, builder.CreateNot(mask), retval->getName() + ".cleared");

                retval = createOrFolder(builder, cleared_retval, maskedinst, cleared_retval->getName() + ".merged");

                printvalueforce(inst);
                auto retvalload = retval;
                printvalueforce(cleared_retval);
                printvalueforce(retvalload);
            }

        }
        return retval;
    }

    void insertInfo(ptrValue pv, idxValue av, memoryValue mv, bool isStore) {
        memInfos.push_back(make_tuple(pv, av, mv, isStore));
    }

    // we use this as a loadValue
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
