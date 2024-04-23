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

    void getBases(void* file_base, ZyanU8* data) {
        file_base = file_base_g;
        data = data_g;
    }


    // sections
    APInt* readMemory(uintptr_t addr, unsigned byteSize) {


        uintptr_t mappedAddr = address_to_mapped_address(file_base_g, addr);
        uintptr_t tempValue;

        if (mappedAddr > 0) {
            std::memcpy(&tempValue, reinterpret_cast<const void*>(data_g + mappedAddr), byteSize);

            APInt readValue(byteSize * 8, tempValue);
            return &readValue;
        }

        return nullptr;
    }

    // TODO
    // 1- if writes into execute section, flag that address, if we execute that address then do fancy stuff to figure out what we wrote so we know what we will be executing
    void writeMemory();

};



namespace GEPStoreTracker {
    // only push stores to here
    vector<memoryInfo> memInfos;

    vector<Instruction*> memInfos2;

    void insertMemoryOp(Instruction* inst) {
        memInfos2.push_back(inst);
    }    
    
    bool overlaps(uint64_t addr1, uint64_t size1, uint64_t addr2, uint64_t size2) {
        return std::max(addr1, addr2) < std::min(addr1 + size1, addr2 + size2);
    }

    uint64_t createmask(long diff) {

        long shift = abs(diff);

        auto mask = 0xFFFFFFFFFFFFFFFFULL << shift * 8;

        return mask ^ -(diff > 0); // 0 or -1 if 0, noop, if -1 xor

    }

    Value* bswapValue(Value* v, IRBuilder<>& builder) {
        Value* newswappedvalue = ConstantInt::get(v->getType(), 0);
        Value* mask = ConstantInt::get(v->getType(), 0xff);
        for (int i = 0; i < v->getType()->getIntegerBitWidth() / 8; i++) {
            // 0xff
            // b = a & 0xff >> 0
            // b = 0x78
            // nb |=  b << 24
            // nb |= 0x78000000
            // 0xff00
            // b = a & 0xff00 >> 8
            // b = 0x56
            // nb |= b << 16
            // nb = 0x78560000
            auto byte = createLShrFolder(builder, createAndFolder(builder, v, mask), i * 8, "shlresultmsb");
            auto shiftby = v->getType()->getIntegerBitWidth() - (i + 1) * 8;
            auto newposbyte = createShlFolder(builder, byte, shiftby);
            newswappedvalue = createOrFolder(builder, newswappedvalue, newposbyte);
            mask = createShlFolder(builder, mask, 8);
        }
        return newswappedvalue;
    }

    Value* solveLoad(LoadInst* load) {
        auto LoadMemLoc = MemoryLocation::get(load);

        const Value* loadPtr = LoadMemLoc.Ptr;
        LocationSize loadsize = LoadMemLoc.Size;

        auto cloadsize = loadsize.getValue();
        printvalueforce2(cloadsize);
        
        // shouldnt happen anyways
        if (!isa<GetElementPtrInst>(loadPtr))
            return nullptr;
        auto loadPtrGEP = cast<GetElementPtrInst>(loadPtr);

        auto loadPointer = loadPtrGEP->getPointerOperand();
        auto loadOffset = loadPtrGEP->getOperand(1);

        Value* retval = nullptr;

        for (auto inst : memInfos2) {

            // we are only interested in previous instructions
            if (!inst->comesBefore(load) )
                break;

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

            printvalueforce2(diff)
            printvalueforce2(memOffsetValue)
            printvalueforce2(loadOffsetValue)

            //if (std::max(loadOffsetValue, memOffsetValue) < std::min(loadOffsetValue + cloadsize, memOffsetValue + MemLoc.Size.getValue() )) {
            if (overlaps(loadOffsetValue, cloadsize, memOffsetValue, MemLoc.Size.getValue() )) {
                
                if (!retval)
                    retval = ConstantInt::get(load->getType(), 0);

                unsigned long long mask = createmask(diff);
                // diff -4 = 0xFF_FF_FF_FF_00_00_00_00
                // diff  4 = 0x00_00_00_00_FF_FF_FF_FF
                printvalueforce2(mask)


                // mask inst here
                // then or with retval

                auto bb = inst->getParent();

                
                IRBuilder<> builder(bb);

                // get negated mask and or then?
                auto maskedinst = builder.CreateAnd(builder.CreateZExt(inst->getOperand(0), retval->getType()) , mask, inst->getName() + ".maskedinst");

                printvalueforce(maskedinst);
                if (diff > 0)
                    maskedinst = builder.CreateShl(maskedinst, diff*8);
                else
                    maskedinst = builder.CreateLShr(maskedinst, -diff*8);

                printvalueforce(maskedinst);

                retval = builder.CreateAnd(retval, mask, inst->getName() + ".masked");
                retval = builder.CreateOr(retval, maskedinst, retval->getName() + ".merged");
                printvalueforce(inst);
                printvalueforce(retval);
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
