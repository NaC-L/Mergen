#include "includes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

struct StoreInfo {
    Value* val;          // The value being stored
    unsigned bitWidth;   // The bit width of the value
};

using namespace llvm;

namespace {
    struct ReplaceLoadWithStoreValuePass : public FunctionPass {
        static char ID;
        ReplaceLoadWithStoreValuePass() : FunctionPass(ID) {}



        bool runOnFunction(Function& F) override {
            bool modified = false;
            std::unordered_map<Value*, std::vector<StoreInfo>> latestStore;

            // store t1 x, ptr y
            // load t2, ptr y
            // replace y with alloc, so it should be
            // %z = alloca t (can it be i128 default?
            //
            // %0 = alloca i32, i32 2
            // store t1 x, ptr %z
            // load t2, ptr %z
            //
            // lets say
            // push rax
            // mov rax, [rsp+4]
            //
            // %0 = alloca i64
            // store %rax, %0
            // %gep = getelementptr i32, ptr %0, i32 1 // gep i32 = align by 4; ptr %0 = from pointer 0; i32 1 = first element
            // %newrax = load i64, ptr %gep
            //
            // however in this case we also need to put it to map;
            // currently we do it like this
            //
            // store t1 x, ptr y
            // load t2, ptr y+4
            // so y and y+4 should share same alloca, but its like
            //
            // store i64 123467812345678, ptr 4
            // load i32, ptr 8




            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {

                if (StoreInst* store = dyn_cast<StoreInst>(&*I)) {
                    Value* storeptr = store->getPointerOperand();
                    Value* val = store->getValueOperand();


                    unsigned bitWidth = val->getType()->getIntegerBitWidth();
                    latestStore[storeptr].emplace_back(StoreInfo{ val, bitWidth });
                }

                // Handling Load Instructions
                else if (LoadInst* load = dyn_cast<LoadInst>(&*I)) {

                    Value* ptr = load->getPointerOperand();

                    unsigned loadBitWidth = load->getType()->getIntegerBitWidth();


                    if (latestStore.find(ptr) != latestStore.end()) {
                        IRBuilder<> builder(load);
                        Value* loadedVal = ConstantInt::get(load->getType(), 0); // Start with 0

                        for (const StoreInfo& storeInfo : latestStore[ptr]) {


                            Value* storedVal = storeInfo.val;

                            unsigned storedBitWidth = storeInfo.bitWidth;



                            Value* mask1 = builder.CreateSub(
                                ConstantInt::get(storedVal->getType(), 0),
                                ConstantInt::get(storedVal->getType(), 1),
                                "mask1");


                            if (mask1->getType()->getIntegerBitWidth() != loadBitWidth)
                                mask1 = builder.CreateZExtOrTrunc(mask1, load->getType(), "mask2");

                            Value* final_mask = builder.CreateSub(ConstantInt::get(load->getType(), -1), mask1, "opt_maskfinal");



                            Value* MaskedStored = builder.CreateAnd(final_mask, loadedVal, "opt_masked"); // 0x3131 | 0xff00, storedVal is cleared its not 0x3100


                            if (storedVal->getType()->getIntegerBitWidth() != loadBitWidth )
                                storedVal = builder.CreateZExtOrTrunc(storedVal, load->getType(),"opt_zext");

                            loadedVal = builder.CreateOr(storedVal, MaskedStored,"opt_or");


                        }
                        load->replaceAllUsesWith(loadedVal);
                        modified = true;
                    }
                }
            }
            return modified; // Return true if the IR was modified
        }
    };
}

char ReplaceLoadWithStoreValuePass::ID = 0;

// function pass for replacing loads with store pass
// before pass ->
// store i64 100, ptr some_mem
// %x = load i64, ptr some_mem
//
// after pass ->
// store i64 100, ptr some_mem
// %x = 100
//
FunctionPass* create_nacibaba_replace_load_with_store_pass() {
    return new ReplaceLoadWithStoreValuePass();
}


namespace {

    struct LoadFromBinaryPass : public FunctionPass {
        static char ID;
        void* binaryBase;
        ZyanU8* data;

        LoadFromBinaryPass(void* base, ZyanU8* fdata) : FunctionPass(ID) {
            binaryBase = base;
            data = fdata;
            // Read the binary into binaryMemory using std::ifstream
            // Set binaryBase to point to binaryMemory.data()
        }


        bool runOnFunction(Function& F) override {
            bool modified = false;
            for (BasicBlock& BB : F) {
                for (Instruction& I : BB) {
                    if (LoadInst* load = dyn_cast<LoadInst>(&I)) {
                        Value* pointerOperand = load->getPointerOperand();

                        if (Operator* op = dyn_cast<Operator>(pointerOperand)) {
                            if (ConstantInt* CI = dyn_cast<ConstantInt>(op->getOperand(0))) {
                                uintptr_t addr = CI->getZExtValue();
                                uintptr_t mappedAddr = address_to_mapped_address(binaryBase, addr);
                                //cout << "mapppedaddr: " << mappedAddr << " addr: " << addr << "\n";
                                if (mappedAddr > 0) {
                                    Type* loadType = load->getType();
                                    unsigned byteSize = loadType->getIntegerBitWidth() / 8;

                                    uintptr_t tempvalue;
                                    std::memcpy(&tempvalue, reinterpret_cast<const void*>( data + mappedAddr), byteSize);


                                    APInt readValue(byteSize * 8, tempvalue);
                                    Constant* newVal = ConstantInt::get(loadType, readValue);
                                    load->replaceAllUsesWith(newVal);

                                    modified = true;
                                }
                            }
                        }
                    }
                }
            }
            return modified;
        }
    };

}  // End of anonymous namespace

char LoadFromBinaryPass::ID = 0;



// basically replace detect binary loads and replace the load with value
//before pass->
// %x = load i64, ptr 0x140002000
// after pass ->
// %x = [whatever the value is at 0x140002000, but no load inst]
FunctionPass* create_nacibaba_replace_load_from_memory(void* binaryBase, ZyanU8* data) {
    return new LoadFromBinaryPass(binaryBase, data);
}




struct StoreInfoFinal {
    Value* val;          // The value being stored
    unsigned bitWidth;   // The bit width of the value
    bool ambigous;
};

using namespace llvm;

namespace {
    struct ReplaceLoadWithStoreValuePassFinal : public FunctionPass {
        static char ID;
        ReplaceLoadWithStoreValuePassFinal() : FunctionPass(ID) {}



        bool runOnFunction(Function& F) override {
            bool modified = false;

            // Maintain a map from a memory location to its latest StoreInst

            // change the map into something so we also store store size with store pointer
            // then when when we are going to merge big loadsize with small storesize, search for older store with same storesize then we merge it using masks to extract the smaller loadsize
            // however we still have the problem of pointer not being the same, so maybe using llvm pass makes more sense
            std::map<Value*, std::vector<StoreInfoFinal>> latestStore;


            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {

                if (StoreInst* store = dyn_cast<StoreInst>(&*I)) {
                    Value* ptr = store->getPointerOperand();
                    Value* val = store->getValueOperand();


                    if (!dyn_cast<ConstantExpr>(ptr)) {

                        for (auto& stores : latestStore) {
                            for (auto& stuff : stores.second) {
                                stuff.ambigous = 1;
                            }
                        }
                        continue;
                    }


                    unsigned bitWidth = val->getType()->getIntegerBitWidth();
                    latestStore[ptr].emplace_back(StoreInfoFinal{ val, bitWidth , 0 });

                }

                // Handling Load Instructions
                else if (LoadInst* load = dyn_cast<LoadInst>(&*I)) {
                    Value* ptr = load->getPointerOperand();
                    unsigned loadBitWidth = load->getType()->getIntegerBitWidth();

                    if (latestStore.find(ptr) != latestStore.end()) {

                        IRBuilder<> builder(load);
                        Value* loadedVal = ConstantInt::get(load->getType(), 1337); // Start with 0
                        unsigned maxamb = 0;
                        bool didchange = false;
                        for (const StoreInfoFinal& storeInfo : latestStore[ptr]) {

                            didchange = false;

                            if (storeInfo.ambigous || maxamb > storeInfo.bitWidth) {
                                maxamb = max(maxamb, storeInfo.bitWidth);
                                continue;
                            }

                            Value* storedVal = storeInfo.val;
                            unsigned storedBitWidth = storeInfo.bitWidth;



                            Value* mask1 = builder.CreateSub(
                                ConstantInt::get(storedVal->getType(), 0),
                                ConstantInt::get(storedVal->getType(), 1),
                                "mask1");


                            if (mask1->getType()->getIntegerBitWidth() != loadBitWidth)
                                mask1 = builder.CreateZExtOrTrunc(mask1, load->getType(), "mask2");

                            Value* final_mask = builder.CreateSub(ConstantInt::get(load->getType(), -1), mask1, "opt_maskfinal");
                            Value* MaskedStored = builder.CreateAnd(final_mask, loadedVal, "opt_masked");

                            storedVal = builder.CreateZExtOrTrunc(storedVal, load->getType(), "opt_zext");

                            loadedVal = builder.CreateOr(storedVal, MaskedStored, "opt_or");

                            didchange = true;

                        }

                        if (didchange) {
                            load->replaceAllUsesWith(loadedVal);
                            modified = true;
                        }

                    }
                }
            }
            return modified; // Return true if the IR was modified
        }
    };
}

char ReplaceLoadWithStoreValuePassFinal::ID = 0;

FunctionPass* create_nacibaba_replace_load_with_store_pass_final() {
    return new ReplaceLoadWithStoreValuePassFinal();
}


namespace {
    struct IntToPtrToAllocaPass : public FunctionPass {
        static char ID;
        IntToPtrToAllocaPass() : FunctionPass(ID) {}

        bool runOnFunction(Function& F) override {
            bool modified = false;
            std::unordered_map<Value*, AllocaInst*> intToAllocaMap;  // Change map key type to Value*
            IRBuilder<> Builder(F.getContext());

            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                // Handling Store Instructions
                if (StoreInst* store = dyn_cast<StoreInst>(&*I)) {
                    if (IntToPtrInst* I2PInst = dyn_cast<IntToPtrInst>(store->getPointerOperand())) {
                        Value* intVal = I2PInst->getOperand(0);  // Change intVal type to Value*
                        if (intToAllocaMap.find(intVal) == intToAllocaMap.end()) {
                            Builder.SetInsertPoint(&*I);
                            AllocaInst* Alloca = Builder.CreateAlloca(Type::getInt64Ty(F.getContext()));
                            intToAllocaMap[intVal] = Alloca;
                        }
                        store->setOperand(1, intToAllocaMap[intVal]);
                        modified = true;
                    }
                }
                // Handling Load Instructions
                else if (LoadInst* load = dyn_cast<LoadInst>(&*I)) {
                    if (IntToPtrInst* I2PInst = dyn_cast<IntToPtrInst>(load->getPointerOperand())) {
                        Value* intVal = I2PInst->getOperand(0);  // Change intVal type to Value*
                        if (intToAllocaMap.find(intVal) != intToAllocaMap.end()) {
                            load->setOperand(0, intToAllocaMap[intVal]);
                            modified = true;
                        }
                    }
                }
            }
            return modified;
        }
    };
}


char IntToPtrToAllocaPass::ID = 0;
static RegisterPass<IntToPtrToAllocaPass> X("inttoptr-to-alloca", "IntToPtr to Alloca Pass");

FunctionPass* createIntToPtrToAllocaPass() {
    return new IntToPtrToAllocaPass();
}





namespace {

    struct IntToPtrStackDSEPass : public FunctionPass {
        static char ID;

        IntToPtrStackDSEPass() : FunctionPass(ID) {
        }

        bool runOnFunction(Function& F) override {
             bool modified = false;
            std::vector<Instruction*> deleteCandidates;

            for (Instruction& I : instructions(F)) {
                if (LoadInst* load = dyn_cast<LoadInst>(&I)) {
                    if (shouldDelete(load->getPointerOperand())) {
                        deleteCandidates.push_back(load);
                    }
                }
                else if (StoreInst* store = dyn_cast<StoreInst>(&I)) {
                    if (shouldDelete(store->getPointerOperand())) {
                        deleteCandidates.push_back(store);
                    }
                }
            }

            for (Instruction* inst : deleteCandidates) {
                inst->eraseFromParent();
                modified = true;
            }

            return modified;
        }

        bool shouldDelete(Value* ptrOperand) {

            if (auto* ce = dyn_cast<ConstantExpr>(ptrOperand)) {
                if (ce->getOpcode() == Instruction::IntToPtr) {
                    if (auto* ci = dyn_cast<ConstantInt>(ce->getOperand(0))) {
                        auto delta = STACKP_VALUE - (int64_t)ci->getZExtValue();
                        return delta > -512 && delta < 4096;
                        //return -512 < ( STACKP_VALUE - ci->getZExtValue() ) < 4096; // Assuming STACKP_VALUE is defined
                    }
                }
            }
            return false;
        }
    };

}  // End of anonymous namespace

char IntToPtrStackDSEPass::ID = 0;



// basically replace detect binary loads and replace the load with value
//before pass->
// %x = load i64, ptr 0x140002000
// after pass ->
// %x = [whatever the value is at 0x140002000, but no load inst]
FunctionPass* CreateIntToPtrStackDSEPass() {
    return new IntToPtrStackDSEPass();
}
