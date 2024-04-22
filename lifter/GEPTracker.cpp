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

namespace GEPStoreTracker {
    // only push stores to here
    queue<memoryInfo> memInfos;

    void insertInfo(ptrValue pv, idxValue av, memoryValue mv, bool isStore) {
        memInfos.push(make_tuple(pv, av, mv, isStore));
    }

    // we use this as a loadValue
    memoryValue getValueAt(IRBuilder<>& builder, ptrValue pv, idxValue iv, unsigned int byteCount) {

        if (!isa<ConstantInt>(iv))
            return nullptr;

        lifterMemoryBuffer2 tempBuffer;
        // only care about %memory values for now 


        // replace queue with vector maybe?
        queue<memoryInfo> memInfos_temp = memInfos;

        while (!memInfos_temp.empty()) {

            auto info = memInfos_temp.front();
            
            memInfos_temp.pop();
            
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
