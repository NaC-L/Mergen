#include "includes.h"
#include "OperandUtils.h"
#include "ROPdetection.h"

#define printvalue(x) \
    outs() << " " #x " : "; x->print(outs()); outs() << "\n";  outs().flush();




Value* computeParityFlag(IRBuilder<>& builder, Value* value) {
    LLVMContext& context = value->getContext(); 

    
    Value* lsb = createAndFolder(builder,value, ConstantInt::get(value->getType(), 0xFF), "lsb");
    Value* parity = ConstantInt::get(Type::getInt1Ty(context), 1);
    for (int i = 0; i < 8; i++) {
        // x ^ (x << i)
        Value* bit = builder.CreateTrunc(builder.CreateLShr(lsb, i), Type::getInt1Ty(value->getContext()),"parityflagbits");

        parity = createXorFolder(builder,parity, bit);

    }
    return parity; // Returns 1 if even parity, 0 if odd
}

Value* computeZeroFlag(IRBuilder<>& builder, Value* value) { // x == 0 = zf
    return builder.CreateICmpEQ(value, ConstantInt::get(value->getType(), 0), "zeroflag");
}

Value* computeSignFlag(IRBuilder<>& builder, Value* value) { // x > 0 = sf
    return builder.CreateICmpSLT(value, ConstantInt::get(value->getType(), 0), "signflag");
}




void branchHelper(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, Value* condition, Value* newRip, string instname, int numbered) {

    auto block = builder.GetInsertBlock();
    block->setName(instname + to_string(numbered));
    auto function = block->getParent();

    auto newcond = createZExtFolder(builder,condition, function->getReturnType());
    auto lastinst = builder.CreateRet(newcond);


    opaque_info opaque = isOpaque(function);

    

    // i want to create a opaque detector here
    // if opaque, return 1 or 2
    // if not, return 0

    auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
    auto result = newRip;
    auto dest = instruction.operands[0];
    switch (opaque) {
    case OPAQUE_TRUE: {

        block->setName("previous" + instname + "-" + to_string(instruction.runtime_address) + "-");
        lastinst->eraseFromParent();
        string block_name = instname + "-jump-" + to_string(instruction.runtime_address) + "-";;
        auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb);
        blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
        break;
    }
    case OPAQUE_FALSE: {

        block->setName("previous" + instname + "-" + to_string(instruction.runtime_address) + "-");
        lastinst->eraseFromParent();
        string block_name2 = instname + "-notjump-" + to_string(instruction.runtime_address) + "-";;
        auto bb2 = BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
        result = ripval;
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
        builder.CreateBr(bb2);

        blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
        result = ripval;
        break;
    }
    case NOT_OPAQUE: {
        llvm::ValueToValueMapTy VMap;
        llvm::Function* conditionFunction = llvm::CloneFunction(function, VMap);
        std::unique_ptr<Module> destinationModule = std::make_unique<Module>("destination_module", function->getContext());
        conditionFunction->removeFromParent();

        destinationModule->getFunctionList().push_back(conditionFunction);
#ifdef _DEVELOPMENT
        std::string Filename_cond = "output_condition_noopt.ll";
        std::error_code EC_cond;
        raw_fd_ostream OS_cond(Filename_cond, EC_cond);
        destinationModule->print(OS_cond, nullptr);
#endif
        final_optpass(conditionFunction);
        std::string Filename = "output_condition.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        destinationModule->print(OS,nullptr);

        lastinst->eraseFromParent();

        block->setName("previous" + instname + "-" + to_string(instruction.runtime_address) + "-");
        // if false, continue from runtime_address
        // if true, continue from runtime_address + dest.imm.value.s

        //builder.CreateCondBr(condition, bb, bb2);
        //auto placeholder = ConstantInt::get(Type::getInt64Ty(context), 0);
        //builder.CreateRet(placeholder);
        //result = createSelectFolder(builder,condition, newRip, ripval);

        cout << "Enter choice (1 for True path, 0 for False path), check output_condition.ll file: ";
        int choice;
        cin >> choice;
        if (choice) {
            string block_name = instname + "-jump-" + to_string(instruction.runtime_address) + "-";;
            auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

            SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
            builder.CreateBr(bb);
            blockAddresses->push_back(make_tuple(dest.imm.value.s + instruction.runtime_address, bb, getRegisterList()));
            break;
        }
        else  {
            string block_name2 = instname + "-notjump-" + to_string(instruction.runtime_address) + "-";;
            auto bb2 = BasicBlock::Create(context, block_name2.c_str(), builder.GetInsertBlock()->getParent());
            result = ripval;
            SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, result);
            builder.CreateBr(bb2);

            blockAddresses->push_back(make_tuple(instruction.runtime_address, bb2, getRegisterList()));
            result = ripval;
            break;
        }


    }
    }

}



namespace mov {


    void lift_movsb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        // Fetch values from SI/ESI/RSI and DI/EDI/RDI
        Value* sourceValue = GetRegisterValue(context, builder, ZYDIS_REGISTER_RSI); // Adjust based on operand size  
        Value* Lvalue = GetRegisterValue(context, builder, ZYDIS_REGISTER_RDI);

        // Fetch the byte from source
        Value* byteToMove = builder.CreateLoad(Type::getInt8Ty(context), getMemoryFromValue(context,builder, sourceValue));

        // Store the byte to destination
        builder.CreateStore(byteToMove, getMemoryFromValue(context, builder, Lvalue));

        // Check the direction flag
        Value* df = getFlag(context, builder, FLAG_DF);

        // Create the value to increment or decrement based on DF
        Value* offset = createSelectFolder(builder,df, ConstantInt::get(sourceValue->getType(), -1), ConstantInt::get(sourceValue->getType(), 1));

        // Update SI/ESI/RSI and DI/EDI/RDI
        Value* updatedSource = createAddFolder(builder,sourceValue, offset);
        Value* updatedDest = createAddFolder(builder,Lvalue, offset);

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RSI, updatedSource); // Adjust based on operand size
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RDI, updatedDest);
    }


    void lift_mov(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, src.size, to_string(instruction.runtime_address));


        if ((dest.type == ZYDIS_OPERAND_TYPE_MEMORY) && (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) && (src.size < dest.size)) {
            Rvalue = GetOperandValue(context, builder, src, dest.size);

        }
#ifdef _DEVELOPMENT
        printvalue(Rvalue);
#endif
        switch (instruction.info.mnemonic) {
        case ZYDIS_MNEMONIC_MOVSX: {
            Rvalue = createSExtFolder(builder,Rvalue, getIntSize(dest.size, context), "movsx-" + to_string(instruction.runtime_address) + "-");
            break;
        }
        case ZYDIS_MNEMONIC_MOVZX: {
            Rvalue = createZExtFolder(builder,Rvalue, getIntSize(dest.size, context), "movzx-" + to_string(instruction.runtime_address) + "-");
            break;
        }
        case ZYDIS_MNEMONIC_MOVSXD: {
            Rvalue = createSExtFolder(builder,Rvalue, getIntSize(dest.size, context), "movsxd-" + to_string(instruction.runtime_address) + "-");
            break;
        }
        }
        SetOperandValue(context, builder, dest, Rvalue, to_string(instruction.runtime_address));


    }



};

namespace cmov {




// cmovbe = cmovbz
void lift_cmovbz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF and CF flags from RFLAGS register
    Value* zf = getFlag(context, builder, FLAG_ZF);
    Value* cf = getFlag(context, builder, FLAG_CF);

    // Check if either ZF or CF is set
    Value* condition = createOrFolder(builder,zf, cf, "cmovbz-or");

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnbz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
    Value* Rvalue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the carry flag (CF) and zero flag (ZF) from the EFLAGS/RFLAGS register
    Value* cf = getFlag(context, builder, FLAG_CF);
    Value* zf = getFlag(context, builder, FLAG_ZF);

    // Check if neither CF nor ZF is set
    Value* nbeCondition = createAndFolder(builder,builder.CreateNot(cf), builder.CreateNot(zf), "nbeCondition");

    // If nbeCondition is true, then the result is the Rvalue; otherwise, it's the Lvalue
    Value* resultValue = createSelectFolder(builder,nbeCondition, Rvalue, Lvalue, "cmovnbe");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}




void lift_cmovz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    instruction.info.raw.disp.value;
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
    Value* Rvalue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the zero flag (ZF) from the EFLAGS/RFLAGS register
    Value* zf = getFlag(context, builder, FLAG_ZF);

    // If ZF is set, then the result is the Rvalue; otherwise, it's the Lvalue
    Value* resultValue = createSelectFolder(builder,zf, Rvalue, Lvalue, "cmovz");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}



// cmovnz = cmovne
void lift_cmovnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    Value* zf = getFlag(context, builder, FLAG_ZF);
    zf = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = createSelectFolder(builder,zf, Rvalue, Lvalue);

    SetOperandValue(context, builder, dest, result);
}
void lift_cmovl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current values of the SF and OF flags from RFLAGS register
    Value* sf = getFlag(context, builder, FLAG_SF);
    Value* of = getFlag(context, builder, FLAG_OF);

    // The condition is true if SF is not equal to OF
    Value* condition = builder.CreateICmpNE(sf, of);

    // Retrieve the values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}


void lift_cmovb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the CF flag from RFLAGS register
    Value* cf = getFlag(context, builder, FLAG_CF);

    // The condition is true if CF is set (i.e., 1)
    Value* condition = builder.CreateICmpEQ(cf, ConstantInt::get(Type::getInt1Ty(context), 1));

    // Retrieve the values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}


void lift_cmovnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Retrieve the values
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
    Value* Rvalue = GetOperandValue(context, builder, src, src.size);

    // Retrieve the carry flag (CF) from the EFLAGS/RFLAGS register
    Value* cf = getFlag(context, builder, FLAG_CF);

    // If CF is not set, then the result is the Rvalue; otherwise, it's the Lvalue
    Value* resultValue = createSelectFolder(builder,builder.CreateNot(cf), Rvalue, Lvalue, "cmovnb");

    // Update the operand with the result
    SetOperandValue(context, builder, dest, resultValue);
}



void lift_cmovns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the SF flag from RFLAGS register
    Value* sf = getFlag(context, builder, FLAG_SF);

    // Check if SF is clear (i.e., 0)
    Value* condition = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Retrieve the values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Conditionally move the value based on the condition
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}
//cmovnl = cmovge
void lift_cmovnl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF flag from RFLAGS register
    Value* sf = getFlag(context, builder, FLAG_SF);
    sf = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = createSelectFolder(builder,sf, Rvalue, Lvalue);

    SetOperandValue(context, builder, dest, result);
}
void lift_cmovs(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the SF flag from RFLAGS register
    Value* sf = getFlag(context, builder, FLAG_SF);

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If SF is set, use Rvalue, otherwise keep Lvalue
    Value* result = createSelectFolder(builder,sf, Rvalue, Lvalue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

    // Operands: the first one is the destination, and the second one is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the ZF, SF, and OF flags from RFLAGS register
    Value* zf = getFlag(context, builder, FLAG_ZF);
    Value* sf = getFlag(context, builder, FLAG_SF);
    Value* of = getFlag(context, builder, FLAG_OF);

    // The condition for CMOVNLE is (ZF = 0 AND SF = OF)
    Value* condition = createAndFolder(builder,
        builder.CreateNot(zf, "notZF"),
        builder.CreateICmpEQ(sf, of, "sf_eq_of"),
        "cmovnle_cond"
    );

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    // Store the result into the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Fetch the ZF, SF, and OF flags
    Value* zf = getFlag(context, builder, FLAG_ZF);
    Value* sf = getFlag(context, builder, FLAG_SF);
    Value* of = getFlag(context, builder, FLAG_OF);

    // Compute the condition (ZF = 1) or (SF != OF)
    Value* sf_neq_of = builder.CreateICmpNE(sf, of);
    Value* condition = createOrFolder(builder,zf, sf_neq_of, "cmovle-or");

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    Value* result = createSelectFolder(builder,condition, Rvalue, Lvalue);

    // Update the destination operand with the result
    SetOperandValue(context, builder, dest, result);
}


void lift_cmovo(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, FLAG_OF);

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If OF is set, use Rvalue, otherwise keep Lvalue
    Value* result = createSelectFolder(builder,of, Rvalue, Lvalue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}
void lift_cmovno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the OF flag from RFLAGS register
    Value* of = getFlag(context, builder, FLAG_OF);

    // Negate the condition since we want the opposite of OF
    of = builder.CreateNot(of, "negateOF");

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If OF is not set (after negation), use Rvalue, otherwise keep Lvalue
    Value* result = createSelectFolder(builder,of, Rvalue, Lvalue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}



void lift_cmovp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the PF flag from RFLAGS register
    Value* pf = getFlag(context, builder, FLAG_PF);


    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
#ifdef _DEVELOPMENT //ZF=0 and SF=OF
    outs() << " pf : "; pf->print(outs()); outs() << "\n";  outs().flush();
    outs() << " Lvalue : "; Rvalue->print(outs()); outs() << "\n";  outs().flush();
    outs() << " Rvalue : "; Lvalue->print(outs()); outs() << "\n";  outs().flush();
#endif
    // Use the select instruction to conditionally move the value
    // If PF is not set (after negation), use Rvalue, otherwise keep Lvalue
    Value* result = createSelectFolder(builder,pf, Rvalue, Lvalue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}

void lift_cmovnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    // Assuming the first operand is the destination and the second is the source
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];

    // Get the current value of the PF flag from RFLAGS register
    Value* pf = getFlag(context, builder, FLAG_PF);

    // Negate the PF flag since we are interested in the not parity condition
    pf = builder.CreateNot(pf, "negatePF");

    // Get values for source and destination operands
    Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
    Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);

    // Use the select instruction to conditionally move the value
    // If PF is not set (after negation), use Rvalue, otherwise keep Lvalue
    Value* result = createSelectFolder(builder,pf, Rvalue, Lvalue);

    // Store the result back to the destination operand
    SetOperandValue(context, builder, dest, result);
}
}

namespace branches {

    // for now assume every call is fake
    void lift_call(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // 0 = function
        // 1 = rip
        // 2 = register rsp
        // 3 = [rsp]
        auto src = instruction.operands[0]; // value that we are pushing
        auto rsp = instruction.operands[2]; // value that we are pushing
        auto rsp_memory = instruction.operands[3]; // value that we are pushing

        auto RspValue = GetOperandValue(context, builder, rsp, rsp.size);

        auto val = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 8); // assuming its x64
        auto result = createSubFolder(builder,RspValue, val, "pushing_newrsp");

        SetOperandValue(context, builder, rsp, result, to_string(instruction.runtime_address)); // sub rsp 8 first,

        auto push_into_rsp = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        SetOperandValue(context, builder, rsp_memory, push_into_rsp, to_string(instruction.runtime_address)); // sub rsp 8 first,


        string block_name = "jmp-call";
        auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());


        builder.CreateBr(bb);

        uintptr_t test = src.imm.value.s + instruction.runtime_address;
#ifdef _DEVELOPMENT
        cout << "jmp address: " << test << "\n";
#endif
        blockAddresses->push_back(make_tuple(test, bb, getRegisterList()));

    }

    int ret_count = 0;
    void lift_ret(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {
        // [0] = rip
        // [1] = rsp
        // [2] = [rsp]

        // if its ret 0x10
        // then its
        // [0] = 0x10
        // [1] = rip
        // [2] = rsp
        // [3] = [rsp]

        auto rspaddr = instruction.operands[2];

        auto rsp = ZYDIS_REGISTER_RSP;
        auto rspvalue = GetRegisterValue(context, builder, rsp);
        if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            rspaddr = instruction.operands[3];
        }

        auto realval = GetOperandValue(context, builder, rspaddr, rspaddr.size);


        auto block = builder.GetInsertBlock();
        block->setName("ret_check" + to_string(ret_count));
        auto function = block->getParent();
        auto lastinst = builder.CreateRet(realval);
#ifdef _DEVELOPMENT
        outs() << "rspvalue: "; rspvalue->print(outs()); outs() << "\n"; outs().flush();
        std::string Filename = "output_rets.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        function->print(OS);
#endif



        uintptr_t destination;

        ROP_info ROP = isROP(function, function->back(), destination);




        lastinst->eraseFromParent();

        block->setName("previousret_block");
#ifdef _DEVELOPMENT
        cout << "rop value: " << ROP << " dest: " << destination << "\n";
#endif
        if (ROP == ROP_return) {

            block->setName("fake_ret");

            string block_name = "jmp_ret-" + to_string(destination) + "-";
            auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

            auto val = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 8); // assuming its x64
            auto result = createAddFolder(builder,rspvalue, val, "ret-new-rsp-" + to_string(instruction.runtime_address) + "-");

            if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                rspaddr = instruction.operands[3];
                auto offset = instruction.operands[0];
                result = createAddFolder(builder,result, ConstantInt::get(result->getType(), instruction.operands[0].imm.value.u));


            }

            SetRegisterValue(context, builder, rsp, result); // then add rsp 8


            builder.CreateBr(bb);

            blockAddresses->push_back(make_tuple(destination, bb, getRegisterList()));
            (*run) = 0;
        }
        else if (ROP == REAL_return) {

            block->setName("real_ret");
            auto rax = GetRegisterValue(context, builder, ZYDIS_REGISTER_RAX);
            builder.CreateRet(createZExtFolder(builder,rax,Type::getInt64Ty(rax->getContext()) ));
            Function* originalFunc_finalnopt = builder.GetInsertBlock()->getParent();
#ifdef _DEVELOPMENT
            std::string Filename_finalnopt = "output_finalnoopt.ll";
            std::error_code EC_finalnopt;
            raw_fd_ostream OS_finalnopt(Filename_finalnopt, EC_finalnopt);

            originalFunc_finalnopt->print(OS_finalnopt);
#endif

            //function->print(outs());

            final_optpass(originalFunc_finalnopt);
#ifdef _DEVELOPMENT
            std::string Filename = "output_finalopt.ll";
            std::error_code EC;
            raw_fd_ostream OS(Filename, EC);
            originalFunc_finalnopt->print(OS);
#endif
            (*run) = 0;
        }



    }
    
    int jmpcount = 0;
    void lift_jmp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jump-xd-" + to_string(instruction.runtime_address) + "-");

        jmpcount++;
        if (jmpcount == 3046) {
            cout << "jmpcount : " << jmpcount << endl;
        }
        if (dest.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            auto rspvalue = GetOperandValue(context, builder, dest, 64);
            auto trunc = createZExtOrTruncFolder(builder,rspvalue, Type::getInt64Ty(context), "jmp-register");


            auto block = builder.GetInsertBlock();
            block->setName("jmp_check" + to_string(ret_count));
            auto function = block->getParent();

            auto lastinst = builder.CreateRet(trunc);

#ifdef _DEVELOPMENT
            std::string Filename = "output_beforeJMP.ll";
            std::error_code EC;
            raw_fd_ostream OS(Filename, EC);
            function->print(OS);
#endif

            uintptr_t destination;
            JMP_info ROP = isJOP(function, destination);


            ValueToValueMapTy VMap_test;

            lastinst->eraseFromParent();

            block->setName("previousjmp_block-" + to_string(destination) + "-");
            //cout << "isJOP:" << ROP << "\n";
            if (ROP == JOP_jmp) {

                string block_name = "jmp-" + to_string(destination) + "-";
                auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

                builder.CreateBr(bb);

                blockAddresses->push_back(make_tuple(destination, bb, getRegisterList()));
                (*run) = 0;
            }
            (*run) = 0;

            //if ROP is not JOP_jmp, then its bugged
            return;
        }


        SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, newRip);

        uintptr_t test = dest.imm.value.s + instruction.runtime_address;
        //cout << "jmp address: " << test << "\n";

        string block_name = "jmp-" + to_string(test) + "-";
        auto bb = BasicBlock::Create(context, block_name.c_str(), builder.GetInsertBlock()->getParent());

        builder.CreateBr(bb);

        blockAddresses->push_back(make_tuple(test, bb, getRegisterList()));
        (*run) = 0;

    }

    int branchnumber = 0;
    // jnz and jne
    void lift_jnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jnz");
#ifdef _DEVELOPMENT
        printvalue(zf);
#endif
        zf = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

        branchHelper(context, builder, instruction, blockAddresses, zf, newRip, "jnz", branchnumber);

        branchnumber++;



    }

    void lift_js(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto sf = getFlag(context, builder, FLAG_SF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "js");


        branchHelper(context, builder, instruction, blockAddresses, sf, newRip, "js", branchnumber);

        branchnumber++;



    }    
    void lift_jns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto sf = getFlag(context, builder, FLAG_SF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jns");

        sf = builder.CreateNot(sf);

        branchHelper(context, builder, instruction, blockAddresses, sf, newRip, "jns", branchnumber);

        branchnumber++;



    }

    void lift_jz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jnz");


        branchHelper(context, builder, instruction, blockAddresses, zf, newRip, "jz", branchnumber);


        branchnumber++;



    }

    void lift_jle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector<tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses) {
        // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

        auto sf = getFlag(context, builder, FLAG_SF);
        auto of = getFlag(context, builder, FLAG_OF);
        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];
        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jle");

        // Check if SF != OF or ZF is set
        auto sf_neq_of = createXorFolder(builder,sf, of, "jle_SF_NEQ_OF");
        auto condition = createOrFolder(builder,sf_neq_of, zf, "jle_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jle", branchnumber);

        branchnumber++;
    }

    void lift_jl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector<tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses) {
        auto sf = getFlag(context, builder, FLAG_SF);
        auto of = getFlag(context, builder, FLAG_OF);

        auto dest = instruction.operands[0];
        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jl");

        // Condition for JL: SF != OF
        auto condition = createXorFolder(builder,sf, of, "jl_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jl", branchnumber);

        branchnumber++;
    }
    void lift_jnl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector<tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses) {
        auto sf = getFlag(context, builder, FLAG_SF);
        auto of = getFlag(context, builder, FLAG_OF);

        auto dest = instruction.operands[0];
        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jnl");
#ifdef _DEVELOPMENT
        printvalue(sf);
        printvalue(of);
#endif
        // Condition for JNL: SF == OF
        auto condition = builder.CreateNot(createXorFolder(builder,sf, of), "jnl_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jnl", branchnumber);

        branchnumber++;
    }


    void lift_jnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector<tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses) {
        // If SF = OF and ZF = 0, then jump. Otherwise, do not jump.

        auto sf = getFlag(context, builder, FLAG_SF);
        auto of = getFlag(context, builder, FLAG_OF);
        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];
        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jnle");

        // Check if SF = OF and ZF is not set
        auto sf_eq_of = createXorFolder(builder,sf, of);
        auto sf_eq_of_not = builder.CreateNot(sf_eq_of, "jnle_SF_EQ_OF_NOT");
        auto zf_not = builder.CreateNot(zf, "jnle_ZF_NOT");
        auto condition = createAndFolder(builder,sf_eq_of_not, zf_not, "jnle_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jnle", branchnumber);

        branchnumber++;
    }



    void lift_jbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // If CF=1 or ZF=1, then jump. Otherwise, do not jump.

        auto cf = getFlag(context, builder, FLAG_CF);
        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jbe");

        // Check if neither CF nor ZF are set
        auto condition = createOrFolder(builder,cf, zf, "jbe_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jbe", branchnumber);


        branchnumber++;
    }



    void lift_jb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // If CF=0, then jump. Otherwise, do not jump.

        auto cf = getFlag(context, builder, FLAG_CF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jb");


        // Check if neither CF nor ZF are set
        auto condition = cf;
        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jb", branchnumber);

        branchnumber++;
    }

    void lift_jnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // If CF=0, then jump. Otherwise, do not jump.

        auto cf = getFlag(context, builder, FLAG_CF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jnb");


        // Check if neither CF nor ZF are set
        auto condition = builder.CreateNot(cf, "notCF");
        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jnb", branchnumber);

        branchnumber++;
    }

    // jnbe == ja
    void lift_jnbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // If CF=0 and ZF=0, then jump. Otherwise, do not jump.

        auto cf = getFlag(context, builder, FLAG_CF);
        auto zf = getFlag(context, builder, FLAG_ZF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);
        auto newRip = createAddFolder(builder,Value, ripval, "jnbe");

        // Check if neither CF nor ZF are set
        auto condition = createAndFolder(builder,builder.CreateNot(cf, "notCF"), builder.CreateNot(zf, "notZF"), "jnbe_ja_Condition");

        branchHelper(context, builder, instruction, blockAddresses, condition, newRip, "jnbe_ja", branchnumber);

        branchnumber++;
    }


    void lift_jo(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto of = getFlag(context, builder, FLAG_OF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jo");


        branchHelper(context, builder, instruction, blockAddresses, of, newRip, "jo", branchnumber);

        branchnumber++;
    }


    void lift_jno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto of = getFlag(context, builder, FLAG_OF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jno");


        of = builder.CreateNot(of);
        branchHelper(context, builder, instruction, blockAddresses, of, newRip, "jno", branchnumber);

        branchnumber++;
    }   
    
    void lift_jp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto pf = getFlag(context, builder, FLAG_PF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jp");


        branchHelper(context, builder, instruction, blockAddresses, pf, newRip, "jp", branchnumber);

        branchnumber++;
    }


    void lift_jnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses) {

        // if 0, then jmp, if not then not jump

        auto pf = getFlag(context, builder, FLAG_PF);

        auto dest = instruction.operands[0];

        auto Value = GetOperandValue(context, builder, dest, 64);
        auto ripval = GetRegisterValue(context, builder, ZYDIS_REGISTER_RIP);

        auto newRip = createAddFolder(builder,Value, ripval, "jnp");

        pf = builder.CreateNot(pf);
#ifdef _DEVELOPMENT
        printvalue(pf)
#endif
        branchHelper(context, builder, instruction, blockAddresses, pf, newRip, "jnp", branchnumber);

        branchnumber++;
    }

}


namespace arithmeticsAndLogical {

    void lift_sbb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* Rvalue = GetOperandValue(context, builder, src, dest.size);
        Value* cf = createZExtOrTruncFolder(builder,getFlag(context, builder, FLAG_CF), Rvalue->getType()); // Initial CF before SBB
        
        // Perform the subtract with borrow operation
        Value* srcPlusCF = createAddFolder(builder,Rvalue, cf, "srcPlusCF");
        Value* tmpResult = createSubFolder(builder,Lvalue, srcPlusCF, "sbbTempResult");
        SetOperandValue(context, builder, dest, tmpResult);


        Value* newCF = builder.CreateICmpULT(Lvalue, srcPlusCF, "newCF");
        Value* sf = computeSignFlag(builder, tmpResult);
        Value* zf = computeZeroFlag(builder, tmpResult);
        Value* pf = computeParityFlag(builder, tmpResult);
        Value* fifteen = ConstantInt::get(Lvalue->getType(), 0xf);
        Value* sub = createSubFolder(builder,createAndFolder(builder,Lvalue, fifteen), createAndFolder(builder,srcPlusCF, fifteen)); // ex: eax = 0xf, CF = 1; sbb eax, 0xf; then AF = 1al
        Value* add = createAddFolder(builder,sub, cf);
        Value* af = builder.CreateICmpUGT(add, ConstantInt::get(add->getType(), 0xf));

        Value* signDest = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0), "signDest");
        Value* signSrc = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
        Value* signResult = builder.CreateICmpSLT(tmpResult, ConstantInt::get(tmpResult->getType(), 0));
        Value* signSrcPlusCF = builder.CreateICmpSLT(srcPlusCF, ConstantInt::get(srcPlusCF->getType(), 0), "signSrcPlusCF");

        // Overflow occurs if: (signDest != signSrcPlusCF) AND (signDest != signResult)
        Value* overflowCond1 = createXorFolder(builder,signDest, signSrcPlusCF, "overflowCond1");
        Value* overflowCond2 = createXorFolder(builder,signDest, signResult, "overflowCond2");
        Value* of = createAndFolder(builder,overflowCond1, overflowCond2, "OF");

        setFlag(context, builder, FLAG_CF, newCF);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);
        setFlag(context, builder, FLAG_AF, af);
        setFlag(context, builder, FLAG_OF, of);
    }


    /*
    
    (* RCL and RCR Instructions *)
    SIZE := OperandSize;
    CASE (determine count) OF
        SIZE := 8: tempCOUNT := (COUNT AND 1FH) MOD 9;
        SIZE := 16: tempCOUNT := (COUNT AND 1FH) MOD 17;
        SIZE := 32: tempCOUNT := COUNT AND 1FH;
        SIZE := 64: tempCOUNT := COUNT AND 3FH;
    ESAC;
    IF OperandSize = 64
        THEN COUNTMASK = 3FH;
        ELSE COUNTMASK = 1FH;
    FI;
    (* RCL Instruction Operation *)
    WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := MSB(DEST);
        DEST := (DEST ∗ 2) + CF;
        CF := tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
    ELIHW;
    IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
    FI;
    */
    void lift_rcl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto count = instruction.operands[1];

        auto* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto* countValue = GetOperandValue(context, builder, count, dest.size);
        auto* carryFlag = getFlag(context, builder, FLAG_CF);

        auto* actualCount = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), dest.size), "actualCount");
        auto* wideType = Type::getIntNTy(context, dest.size * 2);
        auto* wideLvalue = createZExtFolder(builder,Lvalue, wideType);
        auto* shiftedInCF = builder.CreateShl(createZExtFolder(builder,carryFlag, wideType), dest.size,"shiftedincf");
        wideLvalue = createOrFolder(builder,wideLvalue, createZExtFolder(builder,shiftedInCF, wideType, "shiftedInCFExtended"));

        auto* leftShifted = builder.CreateShl(wideLvalue, createZExtFolder(builder,actualCount, wideType, "actualCountExtended"),"leftshifted");
        auto* rightShiftAmount = createSubFolder(builder,ConstantInt::get(actualCount->getType(), dest.size), actualCount,"rightshiftamount");
        auto* rightShifted = builder.CreateLShr(wideLvalue, createZExtFolder(builder,rightShiftAmount, wideType),"rightshifted");
        auto* rotated = createOrFolder(builder,leftShifted, createZExtFolder(builder,rightShifted, wideType, "rightShiftedExtended"));

        auto* result = builder.CreateTrunc(rotated, Lvalue->getType());

        auto* newCFBitPosition = ConstantInt::get(rotated->getType(), dest.size - 1);
        auto* newCF = builder.CreateTrunc(builder.CreateLShr(rotated, newCFBitPosition), Type::getInt1Ty(context),"rclnewcf");

        auto* msbAfterRotate = builder.CreateTrunc(builder.CreateLShr(result, dest.size - 1), Type::getInt1Ty(context),"rclmsbafterrotate");
        auto* newOF = createSelectFolder(builder,builder.CreateICmpEQ(actualCount, ConstantInt::get(actualCount->getType(), 1)), createXorFolder(builder,newCF, msbAfterRotate), getFlag(context, builder, FLAG_OF));

        SetOperandValue(context, builder, dest, result);
        setFlag(context, builder, FLAG_CF, newCF);
        setFlag(context, builder, FLAG_OF, newOF);
    }



    /*
        (* RCL and RCR Instructions *)
    SIZE := OperandSize;
    CASE (determine count) OF
        SIZE := 8: tempCOUNT := (COUNT AND 1FH) MOD 9;
        SIZE := 16: tempCOUNT := (COUNT AND 1FH) MOD 17;
        SIZE := 32: tempCOUNT := COUNT AND 1FH;
        SIZE := 64: tempCOUNT := COUNT AND 3FH;
    ESAC;
    IF OperandSize = 64
        THEN COUNTMASK = 3FH;
        ELSE COUNTMASK = 1FH;
    FI;
    (* RCR Instruction Operation *)
    IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
    FI;
    WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := LSB(SRC);
        DEST := (DEST / 2) + (CF * 2SIZE);
        CF := tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
    ELIHW;

    */void lift_rcr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto count = instruction.operands[1];

        auto* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto* countValue = GetOperandValue(context, builder, count, dest.size);
        auto* carryFlag = getFlag(context, builder, FLAG_CF);

        auto* actualCount = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), dest.size), "actualCount");
        auto* wideType = Type::getIntNTy(context, dest.size * 2);
        auto* wideLvalue = createZExtFolder(builder,Lvalue, wideType);
        auto* shiftedInCF = builder.CreateShl(createZExtFolder(builder,carryFlag, wideType), dest.size);
        wideLvalue = createOrFolder(builder,wideLvalue, createZExtFolder(builder,shiftedInCF, wideType, "shiftedInCFExtended"));

        auto* rightShifted = builder.CreateLShr(wideLvalue, createZExtFolder(builder,actualCount, wideType, "actualCountExtended"),"rightshifted");
        auto* leftShiftAmount = createSubFolder(builder,ConstantInt::get(actualCount->getType(), dest.size), actualCount);
        auto* leftShifted = builder.CreateShl(wideLvalue, createZExtFolder(builder,leftShiftAmount, wideType, "leftShiftAmountExtended"));
        auto* rotated = createOrFolder(builder,rightShifted, leftShifted);

        auto* result = builder.CreateTrunc(rotated, Lvalue->getType());

        auto* newCFBitPosition = ConstantInt::get(rotated->getType(), dest.size - 1);
        auto* newCF = builder.CreateTrunc(builder.CreateLShr(rotated, newCFBitPosition), Type::getInt1Ty(context),"rcrcf");

        auto* msbAfterRotate = builder.CreateTrunc(builder.CreateLShr(result, dest.size - 1), Type::getInt1Ty(context),"rcrmsb");
        auto* newOF = createSelectFolder(builder,builder.CreateICmpEQ(actualCount, ConstantInt::get(actualCount->getType(), 1)), createXorFolder(builder,newCF, msbAfterRotate), getFlag(context, builder, FLAG_OF));

        SetOperandValue(context, builder, dest, result);
        setFlag(context, builder, FLAG_CF, newCF);
        setFlag(context, builder, FLAG_OF, newOF);
    }


    void lift_not(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        auto Rvalue = GetOperandValue(context, builder, dest, dest.size);
        Rvalue = builder.CreateNot(Rvalue, "not");
        SetOperandValue(context, builder, dest, Rvalue);
        //  Flags Affected
        // None

    }

    void lift_neg(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto Rvalue = GetOperandValue(context, builder, dest, dest.size);

        auto cf = builder.CreateICmpNE(Rvalue, ConstantInt::get(Rvalue->getType(), 0), "cf");
        auto result = builder.CreateNeg(Rvalue, "neg");
        SetOperandValue(context, builder, dest, result);

        auto sf = computeSignFlag(builder, result);
        auto zf = computeZeroFlag(builder, result);
        auto pf = computeParityFlag(builder, result);
        Value* fifteen = ConstantInt::get(Rvalue->getType(), 0xf);
        auto af = builder.CreateICmpNE(createAndFolder(builder,Rvalue, fifteen), ConstantInt::get(Rvalue->getType(), 0), "af");

        // OF is cleared nvm
        auto of = ConstantInt::getSigned(Rvalue->getType(), 0);

        // The CF flag set to 0 if the source operand is 0; otherwise it is set to 1. The OF, SF, ZF, AF, and PF flags are set 
        // according to the result.
        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);
        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_AF, af);
    }


    /*
    
    IF 64-Bit Mode and using REX.W
        THEN
            countMASK := 3FH;
        ELSE
            countMASK := 1FH;
    FI
    tempCOUNT := (COUNT AND countMASK);
    tempDEST := DEST;
    WHILE (tempCOUNT ≠ 0)
    DO
        IF instruction is SAL or SHL
            THEN
            CF := MSB(DEST);
        ELSE (* Instruction is SAR or SHR *)
            CF := LSB(DEST);
        FI;
        IF instruction is SAL or SHL
            THEN
                DEST := DEST ∗ 2;
        ELSE
            IF instruction is SAR
                THEN
                    DEST := DEST / 2; (* Signed divide, rounding toward negative infinity *)
            ELSE (* Instruction is SHR *)
                DEST := DEST / 2 ; (* Unsigned divide *)
            FI;
        FI;
        tempCOUNT := tempCOUNT – 1;
    OD;

    (* Determine overflow for the various instructions *)
    IF (COUNT and countMASK) = 1
        THEN
        IF instruction is SAL or SHL
            THEN
            OF := MSB(DEST) XOR CF;
        ELSE
        IF instruction is SAR
            THEN
            OF := 0;
        ELSE (* Instruction is SHR *)
            OF := MSB(tempDEST);
        FI;
    FI;

    ELSE IF (COUNT AND countMASK) = 0
        THEN
        All flags unchanged;
    ELSE (* COUNT not 1 or 0 *)
    OF := undefined;
    FI;
    FI;

    */
    // maybe
    void lift_sar(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto count = instruction.operands[1];

        Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* countValue = GetOperandValue(context, builder, count, dest.size);
        unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
        Value* clampedCount = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth), "clampedCount");
        Value* shiftedValue = builder.CreateAShr(Lvalue, clampedCount, "sar-ashr");

        // Calculate CF (last bit shifted out)
        auto cfValue = builder.CreateTrunc(builder.CreateLShr(Lvalue, createSubFolder(builder,clampedCount, ConstantInt::get(clampedCount->getType(), 1)),"sarcf"), builder.getInt1Ty());
        setFlag(context, builder, FLAG_CF, cfValue);
        Value* sf = computeSignFlag(builder, shiftedValue);
        Value* zf = computeZeroFlag(builder, shiftedValue);
        Value* pf = computeParityFlag(builder, shiftedValue);
        setFlag(context, builder, FLAG_CF, cfValue);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);
        SetOperandValue(context, builder, dest, shiftedValue);


    }
    // maybe
    void lift_shr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto count = instruction.operands[1];

        Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* countValue = GetOperandValue(context, builder, count, dest.size);
        unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
        Value* clampedCount = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth), "clampedCount");
        Value* shiftedValue = builder.CreateLShr(Lvalue, clampedCount, "shr-lshr");

        // Calculate CF (last bit shifted out)
        Value* cfValue = builder.CreateTrunc(builder.CreateLShr(Lvalue, createSubFolder(builder,clampedCount, ConstantInt::get(clampedCount->getType(), 1)),"shrcf"), builder.getInt1Ty());

        // Calculate OF (only on the first shift, OF is the MSB of original value)
        Value* isCountOne = builder.CreateICmpEQ(clampedCount, ConstantInt::get(clampedCount->getType(), 1));
        Value* msbOfOriginal = builder.CreateLShr(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1),"shrmsb");
        msbOfOriginal = createAndFolder(builder,builder.CreateTrunc(msbOfOriginal, Type::getInt1Ty(context)), ConstantInt::get(builder.getInt1Ty(), 1));
        Value* of = createSelectFolder(builder,isCountOne, msbOfOriginal, getFlag(context, builder, FLAG_OF));


        Value* sf = computeSignFlag(builder, shiftedValue);
        Value* zf = computeZeroFlag(builder, shiftedValue);
        Value* pf = computeParityFlag(builder, shiftedValue);

        setFlag(context, builder, FLAG_CF, cfValue);
        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);

        SetOperandValue(context, builder, dest, shiftedValue, to_string(instruction.runtime_address));
    }



    // maybe
    void lift_shl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto count = instruction.operands[1];

        Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* countValue = GetOperandValue(context, builder, count, dest.size);
        unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
        auto bitWidthValue = ConstantInt::get(countValue->getType(), bitWidth);

        Value* clampedCountValue = createAndFolder(builder,countValue, ConstantInt::get(countValue->getType(), bitWidth - 1));

        // Perform the logical left shift
        Value* shiftedValue = builder.CreateShl(Lvalue, clampedCountValue, "shl-shift");

        // Calculate CF (last bit shifted out)
        Value* cfValue = builder.CreateLShr(Lvalue, createSubFolder(builder,bitWidthValue, clampedCountValue),"shlcf");
        Value* one = ConstantInt::get(cfValue->getType(), 1);
        cfValue = createAndFolder(builder,cfValue, one);
        cfValue = builder.CreateTrunc(cfValue, Type::getInt1Ty(context));

        // Calculate OF (only if count is 1)
        Value* isCountOne = builder.CreateICmpEQ(clampedCountValue, ConstantInt::get(clampedCountValue->getType(), 1));

        Value* originalMSB = builder.CreateLShr(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1), "shlmsb");
        originalMSB = createAndFolder(builder,originalMSB, ConstantInt::get(Lvalue->getType(), 1));
        originalMSB = builder.CreateTrunc(originalMSB, Type::getInt1Ty(context));

        // For a 1-bit shift, CF is effectively the original MSB.
        Value* cfAsMSB = builder.CreateTrunc(builder.CreateLShr(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1), "shlcfasmsb"), Type::getInt1Ty(context));

        // The MSB of the result after the shift.
        Value* resultMSB = builder.CreateTrunc(builder.CreateLShr(shiftedValue, ConstantInt::get(shiftedValue->getType(), bitWidth - 1), "shlresultmsb"), Type::getInt1Ty(context));

        // Calculate OF = MSB(result) XOR Original MSB (for 1-bit shifts only).
        Value* ofValue = createSelectFolder(builder,isCountOne, createXorFolder(builder,resultMSB, cfAsMSB), getFlag(context, builder, FLAG_OF));
#ifdef _DEVELOPMENT
        printvalue(isCountOne)
        printvalue(clampedCountValue)
        printvalue(ofValue)
#endif
        // Set flags
        setFlag(context, builder, FLAG_CF, cfValue);
        setFlag(context, builder, FLAG_OF, ofValue);

        Value* sf = computeSignFlag(builder, shiftedValue);
        Value* zf = computeZeroFlag(builder, shiftedValue);
        Value* pf = computeParityFlag(builder, shiftedValue);

        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);

        SetOperandValue(context, builder, dest, shiftedValue);
    }




    void lift_bswap(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];

        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* newswappedvalue = ConstantInt::get(Lvalue->getType(), 0);
        Value* mask = ConstantInt::get(Lvalue->getType(), 0xff);
        for (int i = 0; i < Lvalue->getType()->getIntegerBitWidth() / 8; i++) {
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
            auto byte = builder.CreateLShr(createAndFolder(builder,Lvalue, mask), i * 8, "shlresultmsb");
            auto shiftby = Lvalue->getType()->getIntegerBitWidth() - (i + 1) * 8;
            auto newposbyte = builder.CreateShl(byte, shiftby);
            newswappedvalue = createOrFolder(builder,newswappedvalue, newposbyte);
            mask = builder.CreateShl(mask, 8);
        }


        SetOperandValue(context, builder, dest, newswappedvalue);
    }
    void lift_bswap2(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);

        // Define the intrinsic based on the size of the operand

        /*
        if (ConstantInt* CI = dyn_cast<ConstantInt>(Lvalue)) {
            // Lvalue is a ConstantInt
            unsigned size = Lvalue->getType()->getIntegerBitWidth();

            uint64_t constValue = CI->getZExtValue();
            uint64_t swappedValue = 0;

            for (unsigned i = 0; i < size; i += 8) {
                uint64_t byte_low = (constValue >> i) & 0xff;
                uint64_t byte_high = (constValue >> (size - 8 - i)) & 0xff;

                swappedValue |= (byte_high << i) | (byte_low << (size - 8 - i));
            }

            // Create a new ConstantInt with the byte-swapped value
            Value* newConstInt = ConstantInt::get(context, APInt(size, swappedValue));

            // Replace the original value with the byte-swapped value
            SetOperandValue(context, builder, dest, newConstInt);
            return;
        }*/

        Function* bswapIntrinsic = Intrinsic::getDeclaration(builder.GetInsertBlock()->getModule(), Intrinsic::bswap, Lvalue->getType());
        // Use the intrinsic
        Value* swappedValue = builder.CreateCall(bswapIntrinsic, Lvalue, "bswap");
        SetOperandValue(context, builder, dest, swappedValue);



    }


    void lift_xchg(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, src.size);
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
#ifdef _DEVELOPMENT
        printvalue(Lvalue)
        printvalue(Rvalue)
#endif
        SetOperandValue(context, builder, dest, Rvalue);
        SetOperandValue(context, builder, src, Lvalue);


    }

    // maybe?
    void lift_shld(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto source = instruction.operands[1];
        auto count = instruction.operands[2];

        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto sourceValue = GetOperandValue(context, builder, source, dest.size);
        auto countValue = GetOperandValue(context, builder, count, dest.size);

        unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
        auto effectiveCountValue = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth), "effectiveShiftCount");

        auto shiftedDest = builder.CreateShl(Lvalue, effectiveCountValue, "shiftedDest");
        auto complementCount = createSubFolder(builder,ConstantInt::get(countValue->getType(), bitWidth), effectiveCountValue, "complementCount");
        auto shiftedSource = builder.CreateLShr(sourceValue, complementCount, "shiftedSource");
        auto resultValue = createOrFolder(builder,shiftedDest, shiftedSource, "shldResult");

        auto countIsNotZero = builder.CreateICmpNE(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 0));
        auto lastShiftedBitPosition = createSubFolder(builder,effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
        auto lastShiftedBit = createAndFolder(builder,builder.CreateLShr(Lvalue, lastShiftedBitPosition), ConstantInt::get(Lvalue->getType(), 1),"shldresultmsb");
        auto cf = createSelectFolder(builder,countIsNotZero, builder.CreateTrunc(lastShiftedBit, Type::getInt1Ty(context)), getFlag(context, builder, FLAG_CF));

        // OF calculation, only valid if shift count is 1
        auto isOne = builder.CreateICmpEQ(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
        auto newOF = createXorFolder(builder,builder.CreateLShr(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1)), builder.CreateLShr(resultValue, ConstantInt::get(resultValue->getType(), bitWidth - 1)));
        auto of = createSelectFolder(builder,isOne, builder.CreateTrunc(newOF,Type::getInt1Ty(context)), getFlag(context, builder, FLAG_OF));

        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_OF, of);

        SetOperandValue(context, builder, dest, resultValue);
    }


    // maybe
 void lift_shrd(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
         auto dest = instruction.operands[0];
         auto source = instruction.operands[1];
         auto count = instruction.operands[2];

         auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
         auto sourceValue = GetOperandValue(context, builder, source, dest.size);
         auto countValue = GetOperandValue(context, builder, count, dest.size);

         unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
         auto effectiveCountValue = builder.CreateURem(countValue, ConstantInt::get(countValue->getType(), bitWidth), "effectiveShiftCount");

         auto shiftedDest = builder.CreateLShr(Lvalue, effectiveCountValue, "shiftedDest");
         auto complementCount = createSubFolder(builder,ConstantInt::get(countValue->getType(), bitWidth), effectiveCountValue, "complementCount");
         auto shiftedSource = builder.CreateShl(sourceValue, complementCount, "shiftedSource");
         auto resultValue = createOrFolder(builder,shiftedDest, shiftedSource, "shrdResult");

         // Calculate CF
         auto cfBitPosition = createSubFolder(builder,effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
         Value* cf = builder.CreateLShr(Lvalue, cfBitPosition);
         cf = createAndFolder(builder,cf, ConstantInt::get(cf->getType(), 1));
         cf = builder.CreateTrunc(cf, Type::getInt1Ty(context));

         // Calculate OF, only when count is 1
         Value* isCountOne = builder.CreateICmpEQ(effectiveCountValue, ConstantInt::get(effectiveCountValue->getType(), 1));
         Value* mostSignificantBitOfDest = builder.CreateLShr(Lvalue, ConstantInt::get(Lvalue->getType(), bitWidth - 1));
         mostSignificantBitOfDest = createAndFolder(builder,mostSignificantBitOfDest, ConstantInt::get(mostSignificantBitOfDest->getType(), 1));
         Value* mostSignificantBitOfResult = builder.CreateLShr(resultValue, ConstantInt::get(resultValue->getType(), bitWidth - 1));
         mostSignificantBitOfResult = createAndFolder(builder,mostSignificantBitOfResult, ConstantInt::get(mostSignificantBitOfResult->getType(), 1));
         Value* of = createXorFolder(builder,mostSignificantBitOfDest, mostSignificantBitOfResult);
         of = builder.CreateTrunc(of, Type::getInt1Ty(context));
         of = createSelectFolder(builder,isCountOne, of, ConstantInt::getFalse(context));
         of = createZExtFolder(builder,of, Type::getInt1Ty(context));

         setFlag(context, builder, FLAG_CF, cf);
         setFlag(context, builder, FLAG_OF, of);

         SetOperandValue(context, builder, dest, resultValue);
     }





    void lift_lea(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        auto Rvalue = GetEffectiveAddress(context, builder, src, dest.size);
#ifdef _DEVELOPMENT
        printvalue(Rvalue)
#endif
        SetOperandValue(context, builder, dest, Rvalue);


    }


    void lift_add_sub(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);

        Value* result = nullptr;
        Value* cf = nullptr;
        Value* af = nullptr;
        Value* of = nullptr;
        auto op1sign = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0));
        auto op2sign = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));

        auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
        auto op1LowerNibble = createAndFolder(builder,Lvalue, lowerNibbleMask, "lvalLowerNibble");
        auto op2LowerNibble = createAndFolder(builder,Rvalue, lowerNibbleMask, "rvalLowerNibble");


        switch (instruction.info.mnemonic) {
        case ZYDIS_MNEMONIC_ADD: {
            result = createAddFolder(builder,Lvalue, Rvalue, "realadd-" + to_string(instruction.runtime_address) + "-");
            cf = createOrFolder(builder,builder.CreateICmpULT(result, Lvalue), builder.CreateICmpULT(result, Rvalue));
            auto resultLowerNibble = createAndFolder(builder,result, lowerNibbleMask, "resultLowerNibble");
            auto sumLowerNibble = createAddFolder(builder,op1LowerNibble, op2LowerNibble);
            af = builder.CreateICmpUGT(sumLowerNibble, lowerNibbleMask);
            auto resultSign = builder.CreateICmpSLT(result, ConstantInt::get(Lvalue->getType(), 0));
            auto inputSameSign = builder.CreateICmpEQ(op1sign, op2sign);
            of = createAndFolder(builder,inputSameSign, builder.CreateICmpNE(op1sign, resultSign));

            break;
        }
        case ZYDIS_MNEMONIC_SUB: {
            result = createSubFolder(builder,Lvalue, Rvalue, "realsub-" + to_string(instruction.runtime_address) + "-");



            auto resultSign = builder.CreateICmpSLT(result, ConstantInt::get(Lvalue->getType(), 0));
            auto inputDiffSign = builder.CreateICmpNE(op1sign, op2sign);
            of = createAndFolder(builder,inputDiffSign, builder.CreateICmpNE(op1sign, resultSign));

   
            cf = builder.CreateICmpUGT(Rvalue, Lvalue);
            auto resultLowerNibble = createAndFolder(builder,result, lowerNibbleMask, "resultLowerNibble");
            af = builder.CreateICmpULT(op1LowerNibble, op2LowerNibble);
            break;
        }
        }



        /*
        Flags Affected
        The OF, SF, ZF, AF, CF, and PF flags are set according to the result.
        */
        Value* sign_result = builder.CreateICmpSLT(result, ConstantInt::get(result->getType(), 0));

        auto samesignforof = builder.CreateICmpEQ(op1sign, op2sign);
        auto sf = computeSignFlag(builder,result);
        auto zf = computeZeroFlag(builder,result);
        auto pf = computeParityFlag(builder,result);

        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_AF, af);
        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_PF, pf);
#ifdef _DEVELOPMENT
        printvalue(Lvalue);
        printvalue(Rvalue);
        printvalue(result);
        printvalue(cf);
#endif
        SetOperandValue(context, builder, dest, result);

        // 


    }    
    void lift_imul(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);

        Value* result = builder.CreateMul(Lvalue, Rvalue);

        // Flags
        auto resultType = result->getType();
        auto bitWidth = resultType->getIntegerBitWidth();
        Value* highResult = builder.CreateLShr(result, bitWidth / 2);
        Value* cf = builder.CreateICmpNE(highResult, ConstantInt::get(resultType, 0));
        Value* of = cf;

        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_OF, of);

        SetOperandValue(context, builder, dest, result);
    }
    
    void lift_idiv(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto src = instruction.operands[0];

        auto Rvalue = GetOperandValue(context, builder, src, src.size);

        // Assuming AX, DX:AX, or EDX:EAX/RDX:RAX as dividend depending on operand size
        
        // does zydis already have these operands as hidden?
        Value* dividendLow, * dividendHigh, * dividend;
        if (src.size == 16) {
            dividendLow = GetRegisterValue(context, builder, ZYDIS_REGISTER_AX);

            dividendHigh = GetRegisterValue(context, builder, ZYDIS_REGISTER_DX);
        }
        else if (src.size == 32) {
            dividendLow = GetRegisterValue(context, builder, ZYDIS_REGISTER_EAX);
            dividendHigh = GetRegisterValue(context, builder, ZYDIS_REGISTER_EDX);
        }
        else if (src.size == 64) {
            dividendLow = GetRegisterValue(context, builder, ZYDIS_REGISTER_RAX);
            dividendHigh = GetRegisterValue(context, builder, ZYDIS_REGISTER_RDX);
        }
        else {
            throw std::runtime_error("Unsupported operand size for IDIV.");
        }

        // Combine the high and low parts of the dividend
        auto bitWidth = dividendLow->getType()->getIntegerBitWidth();
        dividend = createOrFolder(builder,builder.CreateShl(dividendHigh, bitWidth), dividendLow);

        // Perform division
        Value* quotient = builder.CreateSDiv(dividend, Rvalue);
        Value* remainder = builder.CreateSRem(dividend, Rvalue);

        // Set the results
        if (src.size == 16) {
            SetRegisterValue(context, builder, ZYDIS_REGISTER_AX, builder.CreateTrunc(quotient, Type::getInt16Ty(context)));
            SetRegisterValue(context, builder, ZYDIS_REGISTER_DX, builder.CreateTrunc(remainder, Type::getInt16Ty(context)));
        }
        else if (src.size == 32) {
            SetRegisterValue(context, builder, ZYDIS_REGISTER_EAX, builder.CreateTrunc(quotient, Type::getInt32Ty(context)));
            SetRegisterValue(context, builder, ZYDIS_REGISTER_EDX, builder.CreateTrunc(remainder, Type::getInt32Ty(context)));
        }
        else if (src.size == 64) {
            SetRegisterValue(context, builder, ZYDIS_REGISTER_RAX, quotient);
            SetRegisterValue(context, builder, ZYDIS_REGISTER_RDX, remainder);
        }
    }




    // extract xor, and, or, ror and rol


    void lift_xor(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];
        auto Rvalue = GetOperandValue(context,builder,src, dest.size);
        auto Lvalue = GetOperandValue(context,builder,dest, dest.size);
        auto result = createXorFolder(builder,Lvalue,Rvalue,"realxor-"+to_string(instruction.runtime_address) + "-");

        //Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

#ifdef _DEVELOPMENT
        printvalue(Lvalue)
        printvalue(Rvalue)
        printvalue(result)
#endif

        auto sf = computeSignFlag(builder, result);
        auto zf = computeZeroFlag(builder, result);
        auto pf = computeParityFlag(builder, result);
        //  The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result. The state of the AF flag is undefined.

        Value* new_flags = setFlag(context, builder, FLAG_SF, sf);
        new_flags = setFlag(context, builder, FLAG_ZF, zf);
        new_flags = setFlag(context, builder, FLAG_PF, pf);

        setFlag(context, builder, FLAG_OF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));
        setFlag(context, builder, FLAG_CF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));



        SetOperandValue(context, builder, dest, result);


    }


    void lift_or(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];
        auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto result = createOrFolder(builder,Lvalue, Rvalue);

        //Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);



        auto sf = computeSignFlag(builder, result);
        auto zf = computeZeroFlag(builder, result);
        auto pf = computeParityFlag(builder, result);

        // The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result. The state of the AF flag is undefined.

        Value* new_flags = setFlag(context, builder, FLAG_SF, sf);
        new_flags = setFlag(context, builder, FLAG_ZF, zf);
        new_flags = setFlag(context, builder, FLAG_PF, pf);


        setFlag(context, builder, FLAG_OF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));
        setFlag(context, builder, FLAG_CF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));

        

        SetOperandValue(context, builder, dest, result);

    }


    void lift_and(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];
        auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto result = createAndFolder(builder,Lvalue, Rvalue);

        //Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);



        auto sf = computeSignFlag(builder, result);
        auto zf = computeZeroFlag(builder, result);
        auto pf = computeParityFlag(builder, result);


        // The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result. The state of the AF flag is undefined.
        Value* new_flags = setFlag(context, builder, FLAG_SF, sf);
        new_flags = setFlag(context, builder, FLAG_ZF, zf);
        new_flags = setFlag(context, builder, FLAG_PF, pf);


        setFlag(context, builder, FLAG_OF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));
        setFlag(context, builder, FLAG_CF, ConstantInt::getSigned(Type::getInt1Ty(context), 0));
        
#ifdef _DEVELOPMENT
printvalue(Lvalue)
printvalue(Rvalue)
printvalue(result)
#endif

        SetOperandValue(context, builder, dest, result);

    }


    /*
    
    tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
    WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := MSB(DEST);
        DEST := (DEST ∗ 2) + tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
    ELIHW;
    IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := LSB(DEST);
    FI;
    IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
    FI
    */
void lift_rol(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
    auto dest = instruction.operands[0];
    auto src = instruction.operands[1];
    auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
    auto Rvalue = GetOperandValue(context, builder, src, dest.size);

    unsigned bitWidth = Lvalue->getType()->getIntegerBitWidth();
    Rvalue = createAndFolder(builder,Rvalue, ConstantInt::get(Rvalue->getType(), bitWidth - 1), "maskRvalue");

    Value* shiftedLeft = builder.CreateShl(Lvalue, Rvalue);
    Value* shiftedRight = builder.CreateLShr(Lvalue, createSubFolder(builder,ConstantInt::get(Rvalue->getType(), bitWidth), Rvalue));
    Value* result = createOrFolder(builder,shiftedLeft, shiftedRight);

    // Calculate CF based on the last bit shifted out
    Value* lastBit = createAndFolder(builder,builder.CreateLShr(Lvalue, createSubFolder(builder,ConstantInt::get(Rvalue->getType(), bitWidth), Rvalue)), ConstantInt::get(Lvalue->getType(), 1));
    Value* cf = builder.CreateTrunc(lastBit, Type::getInt1Ty(context));

    // Calculate OF, which is the XOR of CF and the new MSB of the result
    Value* newMSB = createAndFolder(builder,result, ConstantInt::get(result->getType(), 1ULL << (bitWidth - 1)));
    Value* of = createXorFolder(builder,cf, builder.CreateTrunc(newMSB, Type::getInt1Ty(context)));

    // Use Select to conditionally update OF based on whether the shift amount is 1
    Value* isOneBitRotation = builder.CreateICmpEQ(Rvalue, ConstantInt::get(Rvalue->getType(), 1));
    Value* ofCurrent = getFlag(context, builder, FLAG_OF);
    of = createSelectFolder(builder,isOneBitRotation, of, ofCurrent);

    setFlag(context, builder, FLAG_CF, cf);
    setFlag(context, builder, FLAG_OF, of);

    SetOperandValue(context, builder, dest, result);
}


    /*
    
    tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
    WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := LSB(SRC);
        DEST := (DEST / 2) + (tempCF ∗ 2SIZE);
        tempCOUNT := tempCOUNT – 1;
        OD;
    ELIHW;
    IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := MSB(DEST);
    FI;
    IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR MSB − 1(DEST);
        ELSE OF is undefined;
    FI
    
    */
    void lift_ror(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto Rvalue = GetOperandValue(context, builder, src, dest.size);

        auto size = ConstantInt::getSigned(Lvalue->getType(), Lvalue->getType()->getIntegerBitWidth());
        Rvalue = builder.CreateURem(Rvalue, size);

        Value* result = createOrFolder(builder,builder.CreateLShr(Lvalue, Rvalue), builder.CreateShl(Lvalue, createSubFolder(builder,size, Rvalue)), "ror-" + std::to_string(instruction.runtime_address) + "-");

        Value* msb = builder.CreateLShr(result, createSubFolder(builder,size, ConstantInt::get(context, APInt(Rvalue->getType()->getIntegerBitWidth(), 1))));
        Value* cf = builder.CreateTrunc(msb, Type::getInt1Ty(context), "ror-cf");

        Value* secondMsb = builder.CreateLShr(result, createSubFolder(builder,size, ConstantInt::get(context, APInt(Rvalue->getType()->getIntegerBitWidth(), 2))));
        auto ofDefined = builder.CreateTrunc(createXorFolder(builder,msb, secondMsb), cf->getType());
        auto isOneBitRotation = builder.CreateICmpEQ(Rvalue, ConstantInt::get(context, APInt(Rvalue->getType()->getIntegerBitWidth(), 1)));
        Value* ofCurrent = getFlag(context, builder, FLAG_OF);
        Value* of = createSelectFolder(builder,isOneBitRotation, ofDefined, ofCurrent, "ror-of");

        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_OF, of);

        auto isZeroBitRotation = builder.CreateICmpEQ(Rvalue, ConstantInt::get(context, APInt(Rvalue->getType()->getIntegerBitWidth(), 0)), "iszerobit");
        result = createSelectFolder(builder,isZeroBitRotation, Lvalue, result, "ror-result");

        SetOperandValue(context, builder, dest, result);
    }


    void lift_inc_dec(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto operand = instruction.operands[0];

        Value* originalValue = GetOperandValue(context, builder, operand, operand.size);

        Value* one = ConstantInt::get(originalValue->getType(), 1, true);
        Value* result; 
        Value* of; // Overflow flag
        // The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_INC) {
            // treat it as add r, 1 for flags
            result = createAddFolder(builder,originalValue, one, "inc-" + to_string(instruction.runtime_address) + "-");
            auto* xorResOrig = createXorFolder(builder,originalValue, result);
            auto* xorOrigOne = createXorFolder(builder,originalValue, one);
            auto* ofAnd = createAndFolder(builder,xorResOrig, xorOrigOne);
            of = builder.CreateICmpSLT(ofAnd, ConstantInt::get(ofAnd->getType(), 0));

        }
        else {
            // treat it as sub r, 1 for flags
            result = createSubFolder(builder,originalValue, one, "dec-" + to_string(instruction.runtime_address) + "-");        
            auto* xorResOrig = createXorFolder(builder,originalValue, result);
            auto* xorOrigMinusOne = createXorFolder(builder,originalValue, ConstantInt::get(originalValue->getType(), 1));
            auto* ofAnd = createAndFolder(builder,xorResOrig, xorOrigMinusOne);
            of = builder.CreateICmpSLT(ofAnd, ConstantInt::get(ofAnd->getType(), 0));
            

        }
        Value* sf = computeSignFlag(builder, result);
        Value* zf = computeZeroFlag(builder, result);
        Value* pf = computeParityFlag(builder, result);

        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);
        SetOperandValue(context, builder, operand, result);
    }

    void lift_push(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto src = instruction.operands[0]; // value that we are pushing
        auto dest = instruction.operands[2];
        auto rsp = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

        auto val = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 8); // assuming its x64
        auto result = createSubFolder(builder,RspValue, val, "pushing_newrsp-" + to_string(instruction.runtime_address) + "-");

        SetOperandValue(context, builder, rsp, result, to_string(instruction.runtime_address)); // sub rsp 8 first,


        SetOperandValue(context, builder, dest, Rvalue, to_string(instruction.runtime_address)); // then mov rsp, val

    }

    // (assuming) causing the branch problem
    void lift_pushfq(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto src = instruction.operands[2]; // value that we are pushing rflags
        auto dest = instruction.operands[1];  // [rsp]
        auto rsp = instruction.operands[0]; // rsp

        // TODO: instead of pushing one big flag variable, push them all seperately. This will make it so bits are not confused as values 
         auto Rvalue = GetOperandValue(context, builder, src, dest.size);
        //auto Rvalue = GetRFLAGS(context, builder);
        auto RspValue = GetOperandValue(context, builder, rsp, dest.size);

        auto val = ConstantInt::get(Type::getInt64Ty(context), 8); 
        auto result = createSubFolder(builder,RspValue, val);

        SetOperandValue(context, builder, rsp, result, to_string(instruction.runtime_address)); // sub rsp 8 first,
        
        //pushFlags(context, builder, dest, Rvalue, to_string(instruction.runtime_address));
        SetOperandValue(context, builder, dest, Rvalue, to_string(instruction.runtime_address)); // then mov rsp, val


    }

    void lift_pop(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0]; // value that we are pushing
        auto src = instruction.operands[2];
        auto rsp = instruction.operands[1];

        auto Rvalue = GetOperandValue(context, builder, src, dest.size, to_string(instruction.runtime_address));
        auto RspValue = GetOperandValue(context, builder, rsp, dest.size, to_string(instruction.runtime_address));

        auto val = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 8); // assuming its x64
        auto result = createAddFolder(builder,RspValue, val, "popping_new_rsp-" + to_string(instruction.runtime_address) + "-");
#ifdef _DEVELOPMENT
        printvalue(Rvalue)
#endif
        SetOperandValue(context, builder, dest, Rvalue, to_string(instruction.runtime_address)); // mov val, rsp first

        SetOperandValue(context, builder, rsp, result); // then add rsp 8


    }

    // (assuming) causing the branch problem
    void lift_popfq(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[2]; // value that we are pushing
        auto src = instruction.operands[1];  // [rsp]
        auto rsp = instruction.operands[0]; // rsp

        auto Rvalue = GetOperandValue(context, builder, src, dest.size, to_string(instruction.runtime_address));
        auto RspValue = GetOperandValue(context, builder, rsp, dest.size, to_string(instruction.runtime_address));

        auto val = (ConstantInt*)ConstantInt::getSigned(Type::getInt64Ty(context), 8); // assuming its x64
        auto result = createAddFolder(builder,RspValue, val, "popfq-" + to_string(instruction.runtime_address) + "-");

        SetOperandValue(context, builder, dest, Rvalue, to_string(instruction.runtime_address));  // mov val, rsp first
        SetOperandValue(context, builder, rsp, result, to_string(instruction.runtime_address));  // then add rsp 8



    }

    void lift_adc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        Value* Lvalue = GetOperandValue(context, builder, dest, dest.size);
        Value* Rvalue = GetOperandValue(context, builder, src, dest.size);

        // Get the Carry Flag (CF)
        Value* cf = getFlag(context, builder, FLAG_CF);

        // Extend CF to the size of the destination operand to prepare it for addition
        cf = createZExtFolder(builder,cf, Lvalue->getType());

        // Perform addition
        Value* tempResult = createAddFolder(builder,Lvalue, Rvalue, "adc-temp-" + to_string(instruction.runtime_address) + "-");
        Value* result = createAddFolder(builder,tempResult, cf, "adc-result-" + to_string(instruction.runtime_address) + "-");
        // The OF, SF, ZF, AF, CF, and PF flags are set according to the result.
#ifdef _DEVELOPMENT
        printvalue(Lvalue)
        printvalue(Rvalue)
        printvalue(tempResult)
        printvalue(result)
        
#endif
        auto cfAfterFirstAdd = createOrFolder(builder,builder.CreateICmpULT(tempResult, Lvalue), builder.CreateICmpULT(tempResult, Rvalue));
        auto cfFinal = createOrFolder(builder,cfAfterFirstAdd, builder.CreateICmpULT(result, cf));

        // Adjust flag
        auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
        auto destLowerNibble = createAndFolder(builder,Lvalue, lowerNibbleMask);
        auto srcLowerNibble = createAndFolder(builder,Rvalue, lowerNibbleMask);
        auto sumLowerNibble = createAddFolder(builder,destLowerNibble, srcLowerNibble);
        auto af = builder.CreateICmpUGT(sumLowerNibble, lowerNibbleMask);

        // Overflow flag
        auto resultSign = builder.CreateICmpSLT(result, ConstantInt::get(Lvalue->getType(), 0));
        auto destSign = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0));
        auto srcSign = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
        auto inputSameSign = builder.CreateICmpEQ(destSign, srcSign);
        auto of = createAndFolder(builder,inputSameSign, builder.CreateICmpNE(destSign, resultSign));



        Value* sf = computeSignFlag(builder, result);
        Value* zf = computeZeroFlag(builder, result);
        Value* pf = computeParityFlag(builder, result);

        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_AF, af);
        setFlag(context, builder, FLAG_CF, cfFinal);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);


        // Store the result in the destination operand
        SetOperandValue(context, builder, dest, result);
    }


    void lift_xadd(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming the first operand is the destination and the second operand is the source
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        // Retrieve the values
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto Rvalue = GetOperandValue(context, builder, src, src.size);

        // Calculate the sum of Lvalue and Rvalue
        Value* sumValue = createAddFolder(builder,Lvalue, Rvalue, "xadd_sum-" + to_string(instruction.runtime_address) + "-");

        // The result to be stored in the destination is sumValue
        SetOperandValue(context, builder, dest, sumValue, to_string(instruction.runtime_address));

        // The result to be stored in the source is the original Lvalue
        SetOperandValue(context, builder, src, Lvalue, to_string(instruction.runtime_address));
        /*
        TEMP := SRC + DEST;
        SRC := DEST;
        DEST := TEMP;
        */
#ifdef _DEVELOPMENT
        printvalue(Lvalue)
        printvalue(Rvalue)
        printvalue(sumValue)
#endif
        auto cf = createOrFolder(builder,builder.CreateICmpULT(sumValue, Lvalue), builder.CreateICmpULT(sumValue, Rvalue));

        // Adjust flag
        auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
        auto destLowerNibble = createAndFolder(builder,Lvalue, lowerNibbleMask);
        auto srcLowerNibble = createAndFolder(builder,Rvalue, lowerNibbleMask);
        auto sumLowerNibble = createAddFolder(builder,destLowerNibble, srcLowerNibble);
        auto af = builder.CreateICmpUGT(sumLowerNibble, lowerNibbleMask);

        // Overflow flag
        auto resultSign = builder.CreateICmpSLT(sumValue, ConstantInt::get(Lvalue->getType(), 0));
        auto destSign = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0));
        auto srcSign = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
        auto inputSameSign = builder.CreateICmpEQ(destSign, srcSign);
        auto of = createAndFolder(builder,inputSameSign, builder.CreateICmpNE(destSign, resultSign));


        Value* sf = computeSignFlag(builder, sumValue);
        Value* zf = computeZeroFlag(builder, sumValue);
        Value* pf = computeParityFlag(builder, sumValue);

        setFlag(context, builder, FLAG_OF, of);
        setFlag(context, builder, FLAG_AF, af);
        setFlag(context, builder, FLAG_CF, cf);
        setFlag(context, builder, FLAG_SF, sf);
        setFlag(context, builder, FLAG_ZF, zf);
        setFlag(context, builder, FLAG_PF, pf);

        // The CF, PF, AF, SF, ZF, and OF flags are set according to the result of the addition, which is stored in the destination operand.
    }

    void lift_test(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        Value* Lvalue = GetOperandValue(context, builder, instruction.operands[0], instruction.operands[0].size);
        Value* Rvalue = GetOperandValue(context, builder, instruction.operands[1], instruction.operands[0].size);

        // Compute the bitwise AND result
        Value* testResult = createAndFolder(builder,Lvalue, Rvalue, "testAnd");

        // OF and CF are cleared
        Value* of = ConstantInt::get(Type::getInt64Ty(context), 0, "of");
        Value* cf = ConstantInt::get(Type::getInt64Ty(context), 0, "cf");

        // Calculate SF, ZF, and PF based on testResult
        Value* sf = builder.CreateICmpSLT(testResult, ConstantInt::get(testResult->getType(), 0), "sf");
        Value* zf = builder.CreateICmpEQ(testResult, ConstantInt::get(testResult->getType(), 0), "zf");
        Value* pf = computeParityFlag(builder, testResult);

        //Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

        Value* new_flags = setFlag(context, builder, FLAG_OF, of);
        new_flags = setFlag(context, builder, FLAG_CF, cf);
        new_flags = setFlag(context, builder, FLAG_SF, sf);
        new_flags = setFlag(context, builder, FLAG_ZF, zf);
        new_flags = setFlag(context, builder, FLAG_PF, pf);

        
    }

    void lift_cmp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Compute the difference

        Value* Lvalue = GetOperandValue(context, builder, instruction.operands[0], instruction.operands[0].size);
        Value* Rvalue = GetOperandValue(context, builder, instruction.operands[1], instruction.operands[0].size);

        Value* cmpResult = createSubFolder(builder,Lvalue, Rvalue);
        // Calculate flags based on cmpResult
        Value* signL = builder.CreateICmpSLT(Lvalue, ConstantInt::get(Lvalue->getType(), 0));
        Value* signR = builder.CreateICmpSLT(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
        Value* signResult = builder.CreateICmpSLT(cmpResult, ConstantInt::get(cmpResult->getType(), 0));

        // Overflow flag: (Lsign and not Rsign and not ResultSign) or (not Lsign and Rsign and ResultSign)
        Value* of = createOrFolder(builder,
            createAndFolder(builder,signL, createAndFolder(builder,builder.CreateNot(signR), builder.CreateNot(signResult), "cmp-and1-")),
            createAndFolder(builder,builder.CreateNot(signL), createAndFolder(builder,signR, signResult), "cmp-and2-"), "cmp-OF-or"
        );

        Value* cf = builder.CreateICmpULT(Lvalue, Rvalue);
        Value* zf = builder.CreateICmpEQ(cmpResult, ConstantInt::get(cmpResult->getType(), 0));
        Value* sf = builder.CreateICmpSLT(cmpResult, ConstantInt::get(cmpResult->getType(), 0));
        Value* pf = computeParityFlag(builder, cmpResult);

        //Value* old_flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

        Value* new_flags = setFlag(context, builder, FLAG_OF, of);
        new_flags = setFlag(context, builder, FLAG_CF, cf);
        new_flags = setFlag(context, builder, FLAG_SF, sf);
        new_flags = setFlag(context, builder, FLAG_ZF, zf);
        new_flags = setFlag(context, builder, FLAG_PF, pf);
        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, new_flags);
    }


    // maybe will edit
    void lift_rdtsc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto rdtscCall = builder.CreateIntrinsic(llvm::Intrinsic::readcyclecounter, {}, {});
        auto edxPart = builder.CreateLShr(rdtscCall, 32, "to_edx");
        auto eaxPart = builder.CreateTrunc(rdtscCall, llvm::Type::getInt32Ty(context), "to_eax");
        SetRegisterValue(context, builder, ZYDIS_REGISTER_EDX, edxPart);
        SetRegisterValue(context, builder, ZYDIS_REGISTER_EAX, eaxPart);

    }

}

namespace flagOperation {
    void lift_setnz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        Value* zf = getFlag(context, builder, FLAG_ZF);

        // Create a check for ZF being 0 (because SETNZ sets byte to 1 if ZF = 0)
        Value* result = createZExtFolder(builder,builder.CreateNot(zf), Type::getInt8Ty(context));

        // Store the result in the destination operand
        SetOperandValue(context, builder, dest, result);

    }
    void lift_seto(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        Value* of = getFlag(context, builder, FLAG_OF);

        // Convert the i1 (boolean) value of OF to an 8-bit integer
        Value* result = createZExtFolder(builder,of, Type::getInt8Ty(context));

        SetOperandValue(context, builder, dest, result);
    }
    void lift_setno(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        Value* of = getFlag(context, builder, FLAG_OF);

        Value* notOf = builder.CreateNot(of, "notOF");

        // Convert the i1 (boolean) value of notOf to an 8-bit integer
        Value* result = createZExtFolder(builder,notOf, Type::getInt8Ty(context));

        SetOperandValue(context, builder, dest, result);
    }

    void lift_setnb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        Value* cf = getFlag(context, builder, FLAG_CF);

        // Check for CF being 0 (because SETNB sets byte to 1 if CF = 0)
        Value* result = builder.CreateICmpEQ(cf, ConstantInt::get(Type::getInt1Ty(context), 0));

        // Zero extend the result to byte size, since SETNB works on bytes
        Value* byteResult = createZExtFolder(builder,result, Type::getInt8Ty(context));

        SetOperandValue(context, builder, dest, byteResult);
    }

    void lift_setbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the CF and ZF flags
        Value* cf = getFlag(context, builder, FLAG_CF);
        Value* zf = getFlag(context, builder, FLAG_ZF);

        // The condition is (CF=1 or ZF=1)
        Value* condition = createOrFolder(builder,cf, zf, "setbe-or");

        // Convert condition from i1 to i8
        Value* result = createZExtFolder(builder,condition, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }

    void lift_setnbe(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the CF and ZF flags
        Value* cf = getFlag(context, builder, FLAG_CF);
        Value* zf = getFlag(context, builder, FLAG_ZF);

        // The condition is (CF=0 and ZF=0)
        Value* condition = createAndFolder(builder,builder.CreateNot(cf), builder.CreateNot(zf), "setnbe-and");

        // Convert condition from i1 to i8
        Value* result = createZExtFolder(builder,condition, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }


    void lift_setns(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        // Get the current value of the SF flag from RFLAGS register
        Value* sf = getFlag(context, builder, FLAG_SF);

        // Check for SF being 0 (because SETNS sets byte to 1 if SF = 0)
        Value* result = builder.CreateICmpEQ(sf, ConstantInt::get(Type::getInt1Ty(context), 0));

        // Zero extend the result to byte size, since SETNS works on bytes
        Value* byteResult = createZExtFolder(builder,result, Type::getInt8Ty(context));

        // Store the result in the destination operand
        SetOperandValue(context, builder, dest, byteResult);
    }

    void lift_setp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Get the PF bit from RFLAGS register
        Value* pf = getFlag(context, builder, FLAG_PF);

        // Convert PF to an 8-bit integer
        Value* result = createZExtFolder(builder,pf, Type::getInt8Ty(context));

        // Assuming the first operand is the destination
        auto dest = instruction.operands[0];

        // Set the value of the destination operand
        SetOperandValue(context, builder, dest, result);
    }

    void lift_setnp(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];

        // Retrieve the Parity Flag (PF) from the EFLAGS/RFLAGS register
        Value* pf = getFlag(context, builder, FLAG_PF);

        // The result is 1 if PF is clear and 0 otherwise
        Value* resultValue = createZExtFolder(builder,builder.CreateNot(pf), Type::getInt8Ty(context));

        // Update the operand with the result
        SetOperandValue(context, builder, dest, resultValue);
    }


    void lift_setb(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        // The destination is usually a single byte in memory or a byte-sized register.
        auto dest = instruction.operands[0];

        // Get the current value of the CF flag from RFLAGS register
        Value* cf = getFlag(context, builder, FLAG_CF);

        // Convert the i1 (boolean) value of CF to an 8-bit integer
        Value* result = createZExtFolder(builder,cf, Type::getInt8Ty(context));

        // Store the result into the destination operand
        SetOperandValue(context, builder, dest, result);
    }


    void lift_sets(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the SF flag
        Value* sf = getFlag(context, builder, FLAG_SF);

        // Convert SF condition from i1 to i8
        Value* result = createZExtFolder(builder,sf, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }


    void lift_setz(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming the operand is the destination
        auto dest = instruction.operands[0];

        // Get the current value of the ZF flag from RFLAGS register
        Value* zf = getFlag(context, builder, FLAG_ZF);

        // ZF is usually represented in LLVM as a i1 type (boolean).
        // Extend this to 8 bits to match the size of the SETZ destination.
        Value* extendedZF = createZExtFolder(builder,zf, Type::getInt8Ty(context), "setz_extend");

        // Store the result to the destination operand
        SetOperandValue(context, builder, dest, extendedZF);
    }

    void lift_setnle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];

        // Get the current values of the ZF, SF, and OF flags from RFLAGS register
        Value* zf = getFlag(context, builder, FLAG_ZF);
        Value* sf = getFlag(context, builder, FLAG_SF);
        Value* of = getFlag(context, builder, FLAG_OF);

        // Check for ZF being 0
        Value* zfNotSet = builder.CreateICmpEQ(zf, ConstantInt::get(Type::getInt1Ty(context), 0));

        // Check for SF=OF
        Value* sfEqualsOf = builder.CreateICmpEQ(sf, of);

#ifdef _DEVELOPMENT //ZF=0 and SF=OF
        printvalue(zf)
        printvalue(sf)
        printvalue(of)
#endif
        // Combine the two conditions with AND operation
        Value* combinedCondition = createAndFolder(builder,zfNotSet, sfEqualsOf, "setnle-and");

        // Zero extend the result to byte size, since SET instructions work on bytes
        Value* byteResult = createZExtFolder(builder,combinedCondition, Type::getInt8Ty(context));

        // Store the result in the destination operand
        SetOperandValue(context, builder, dest, byteResult);
    }

    void lift_setle(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the ZF, SF, and OF flags
        Value* zf = getFlag(context, builder, FLAG_ZF);
        Value* sf = getFlag(context, builder, FLAG_SF);
        Value* of = getFlag(context, builder, FLAG_OF);

        // Compute the condition (ZF=1) OR (SF != OF)
        Value* sf_ne_of = builder.CreateICmpNE(sf, of);
        Value* condition = createOrFolder(builder,zf, sf_ne_of, "setle-or");

        // Convert the condition from i1 to i8
        Value* result = createZExtFolder(builder,condition, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }

    void lift_setnl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the SF and OF flags
        Value* sf = getFlag(context, builder, FLAG_SF);
        Value* of = getFlag(context, builder, FLAG_OF);

        // Compute the condition (SF = OF)
        Value* condition = builder.CreateICmpEQ(sf, of);

        // Convert the condition from i1 to i8
        Value* result = createZExtFolder(builder,condition, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }

    void lift_setl(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Fetch the SF and OF flags
        Value* sf = getFlag(context, builder, FLAG_SF);
        Value* of = getFlag(context, builder, FLAG_OF);

        // Compute the condition (SF != OF)
        Value* condition = builder.CreateICmpNE(sf, of);

        // Convert the condition from i1 to i8
        Value* result = createZExtFolder(builder,condition, Type::getInt8Ty(context));

        // Set the result to the destination operand
        auto dest = instruction.operands[0];
        SetOperandValue(context, builder, dest, result);
    }



    void lift_bt(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming the first operand is the destination and the second is the bit index
        auto dest = instruction.operands[0];
        auto bitIndex = instruction.operands[1];

        // Retrieve the values
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto bitIndexValue = GetOperandValue(context, builder, bitIndex, dest.size);

        auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), Lvalue->getType()->getIntegerBitWidth()));

        // Create a mask to test the bit
        auto mask = builder.CreateShl(ConstantInt::get(Lvalue->getType(), 1), adjustedBitIndexValue);


        // Test the bit by performing bitwise AND
        auto testValue = createAndFolder(builder,Lvalue, mask, "bt");

        // Check if the bit is set. This will be a non-zero value if the bit was set.
        auto isBitSet = builder.CreateICmpNE(testValue, ConstantInt::get(Lvalue->getType(), 0), "btisbitset");

    }


    void lift_btr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming the first operand is the destination and the second is the bit index
        auto dest = instruction.operands[0];
        auto bitIndex = instruction.operands[1];

        // Retrieve the values
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto bitIndexValue = GetOperandValue(context, builder, bitIndex, bitIndex.size);

        // Calculate the modulo of the bit index
        auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), Lvalue->getType()->getIntegerBitWidth()), "btr-urem");

        adjustedBitIndexValue = createZExtOrTruncFolder(builder,adjustedBitIndexValue, Lvalue->getType(), "castedBitIndex");

        // Create a mask to test the bit

        // Create a mask to clear the bit
        auto mask = builder.CreateShl(ConstantInt::get(Lvalue->getType(), 1), adjustedBitIndexValue, "btr-mask");
        mask = builder.CreateNot(mask, "btr-not");

        // Clear the bit
        auto resultValue = createAndFolder(builder,Lvalue, mask, "btr-clear-" + to_string(instruction.runtime_address) + "-");

        // Update the operand with the result
        SetOperandValue(context, builder, dest, resultValue);



    }

    void lift_bsr2(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        // Retrieve the value for the source operand
        Value* Rvalue = GetOperandValue(context, builder, src, src.size);

        // Define the intrinsic for counting leading zeros
        Function* ctlzIntrinsic = Intrinsic::getDeclaration(
            builder.GetInsertBlock()->getModule(),
            Intrinsic::ctlz,
            Rvalue->getType()
        );

        // Call the intrinsic to count leading zeros
        Value* leadingZeros = builder.CreateCall(ctlzIntrinsic, { Rvalue, ConstantInt::getFalse(context) });

        // Calculate the index of the highest set bit
        Value* bitPosition = createSubFolder(builder,
            ConstantInt::get(Rvalue->getType(), src.size * 8 - 1),
            leadingZeros
        );

        // Set the result into the destination operand
        SetOperandValue(context, builder, dest, bitPosition);
    }

    void lift_bsr(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        // Retrieve the value for the source operand
        Value* Rvalue = GetOperandValue(context, builder, src, src.size);

        // Bit width of the source value
        unsigned bitWidth = Rvalue->getType()->getIntegerBitWidth();

        // Prepare a loop to find the most significant bit that is set
        Value* index = ConstantInt::get(Rvalue->getType(), bitWidth - 1);
        Value* zeroVal = ConstantInt::get(Rvalue->getType(), 0);
        Value* oneVal = ConstantInt::get(Rvalue->getType(), 1);

        // Placeholder for the result (initialized to -1 to indicate no bits are set)
        Value* bitPosition = ConstantInt::get(Rvalue->getType(), -1);

        // Loop through each bit from MSB to LSB
        for (unsigned i = 0; i < bitWidth; ++i) {
            // Create mask for current bit
            Value* mask = builder.CreateShl(oneVal, index);

            // Test if the bit is set
            Value* test = createAndFolder(builder, Rvalue, mask);
            Value* isBitSet = builder.CreateICmpNE(test, zeroVal);

            // Use the first bit set as the result and break the loop
            Value* tmpPosition = createSelectFolder(builder, isBitSet, index, bitPosition);

            // Only update bitPosition if it has not been set yet (-1)
            Value* isPositionUnset = builder.CreateICmpEQ(bitPosition, ConstantInt::get(Rvalue->getType(), -1));
            bitPosition = createSelectFolder(builder, isPositionUnset, tmpPosition, bitPosition);

            // Decrement index for next iteration
            index = createSubFolder(builder, index, oneVal);
        }

        // Set the result into the destination operand
        SetOperandValue(context, builder, dest, bitPosition);
    }

    void lift_bsf(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto dest = instruction.operands[0];
        auto src = instruction.operands[1];

        // Get value for source operand
        Value* Rvalue = GetOperandValue(context, builder, src, src.size);

        // Check if source is zero and set the zero flag accordingly
        Value* isZero = builder.CreateICmpEQ(Rvalue, ConstantInt::get(Rvalue->getType(), 0));
        setFlag(context, builder, FLAG_ZF, isZero);

        Type* intType = Rvalue->getType();
        uint64_t intWidth = intType->getIntegerBitWidth();

        Value* result = ConstantInt::get(intType, intWidth); // Default to max width indicating no bits found
        Value* one = ConstantInt::get(intType, 1);

        Value* continuecounting = ConstantInt::get(Type::getInt1Ty(context), 1);
        for (uint64_t i = 0; i < intWidth; ++i) {
            Value* bitMask = builder.CreateShl(one, ConstantInt::get(intType, i));
            Value* bitSet = createAndFolder(builder,Rvalue, bitMask);
            Value* isBitZero = builder.CreateICmpEQ(bitSet, ConstantInt::get(intType, 0));
            // continue until isBitZero is 1
            // 0010
            // if continuecounting, select
            Value* possibleResult = ConstantInt::get(intType, i);
            Value* condition = createAndFolder(builder, continuecounting, isBitZero);
            continuecounting = builder.CreateNot(isBitZero);
            result = createSelectFolder(builder, condition, result, possibleResult, "updateResultOnFirstNonZeroBit");
        }

        // Store the result in the destination operand
        SetOperandValue(context, builder, dest, result);
    }





    void lift_btc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming the first operand is the destination and the second is the bit index
        auto dest = instruction.operands[0];
        auto bitIndex = instruction.operands[1];

        // Retrieve the values
        auto Lvalue = GetOperandValue(context, builder, dest, dest.size);
        auto bitIndexValue = GetOperandValue(context, builder, bitIndex, bitIndex.size);

        // Calculate the modulo of the bit index
        auto adjustedBitIndexValue = builder.CreateURem(bitIndexValue, ConstantInt::get(bitIndexValue->getType(), Lvalue->getType()->getIntegerBitWidth()));

        adjustedBitIndexValue = createZExtOrTruncFolder(builder,adjustedBitIndexValue, Lvalue->getType(), "castedBitIndex");

        // Create a mask to test the bit
        auto mask = builder.CreateShl(ConstantInt::get(Lvalue->getType(), 1), adjustedBitIndexValue, "btc-mask");

        // Test the bit by performing bitwise AND
        auto testValue = createAndFolder(builder,Lvalue, mask, "btc-and");
        auto isBitSet = builder.CreateICmpNE(testValue, ConstantInt::get(Lvalue->getType(), 0));

        // Toggle the bit by using XOR
        auto resultValue = createXorFolder(builder,Lvalue, mask, "btc-xor");

        // Update the operand with the result
        SetOperandValue(context, builder, dest, resultValue);
        setFlag(context, builder, FLAG_CF, isBitSet);
    }




    void lift_lahf(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {


        auto flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
        auto sf = getFlag(context, builder, FLAG_SF);
        auto zf = getFlag(context, builder, FLAG_ZF);
        auto af = getFlag(context, builder, FLAG_AF);
        auto pf = getFlag(context, builder, FLAG_PF);
        auto cf = getFlag(context, builder, FLAG_CF);

        Value* Rvalue = createOrFolder(builder,
            builder.CreateShl(sf, 7),
            createOrFolder(builder,
                builder.CreateShl(zf, 6),
                createOrFolder(builder,
                    builder.CreateShl(af, 4),
                    createOrFolder(builder,
                        builder.CreateShl(pf, 2), cf, "lahf-or-3"), "lahf-or-2"), "lahf-or1"), "lahf-or");


        SetRegisterValue(context, builder, ZYDIS_REGISTER_AH, Rvalue);


    }

    void lift_stc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {


        setFlag(context, builder, FLAG_CF, ConstantInt::get(Type::getInt1Ty(context), 1) );

        //auto flags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);

        //auto Rvalue = createAndFolder(builder,flags, ConstantInt::get(flags->getType(), 1), "stc-and");


        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, Rvalue);


    }

    void lift_cmc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        /*
        Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

        // Get the CF bit
        Value* cf = getFlag(context, builder, FLAG_CF);

        // Toggle the CF bit (complement)
        Value* toggledCF = createXorFolder(builder,cf, ConstantInt::get(cf->getType(), 1), "cmd-xor");

        // Set the toggled value back into the EFLAGS/RFLAGS register
        Value* updatedEflags = setFlag(context, builder, FLAG_CF, toggledCF);

        SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit
        */

        Value* cf = getFlag(context, builder, FLAG_CF);
        Value* one = ConstantInt::get(cf->getType(), 1);
        setFlag(context, builder, FLAG_CF, createXorFolder(builder,cf,one));

    }
    void lift_clc(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        //Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

        // Clear the CF bit
        Value* clearedCF = ConstantInt::get(Type::getInt1Ty(context), 0);

        // Set the cleared CF value into the EFLAGS/RFLAGS register
        setFlag(context, builder, FLAG_CF, clearedCF);

        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

    }

    void lift_cld(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        //Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_EFLAGS for 32-bit

        // Clear the DF bit
        Value* clearedDF = ConstantInt::get(Type::getInt1Ty(context), 0);

        // Set the cleared value back into the EFLAGS/RFLAGS register
        Value* updatedEflags = setFlag(context, builder, FLAG_DF, clearedDF);

        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_EFLAGS for 32-bit
    }


    void lift_cli(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {

        //Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS); // Or ZYDIS_REGISTER_RFLAGS for 64-bit

        // Get the CF bit
        //Value* intf = getFlag(context, builder, FLAG_IF);

        // Toggle the CF bit (complement)
        Value* resetIF = ConstantInt::get(Type::getInt1Ty(context), 0);

        // Set the toggled value back into the EFLAGS/RFLAGS register
        Value* updatedEflags = setFlag(context, builder, FLAG_IF, resetIF);

        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, updatedEflags); // Or ZYDIS_REGISTER_RFLAGS for 64-bit


    }
    void lift_bts(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        auto base = instruction.operands[0];
        auto offset = instruction.operands[1];

        // Convert the offset into a bit offset
        unsigned baseBitWidth = base.size; // assuming base.size is in bytes

        // Convert the offset into a bit offset
        Value* bitOffset = GetOperandValue(context, builder, offset, offset.size);

        // Mask bitOffset to prevent undefined behavior due to shifting with too large values
        Value* bitOffsetMasked = createAndFolder(builder,bitOffset, ConstantInt::get(bitOffset->getType(), baseBitWidth - 1), "bitOffsetMasked");

        // Extract the bit from the base operand
        Value* baseVal = GetOperandValue(context, builder, base, base.size);
        Value* bit = builder.CreateLShr(baseVal, bitOffsetMasked, "bts-lshr-" + to_string(instruction.runtime_address) + "-");
        Value* one = ConstantInt::get(bit->getType(), 1);
        bit = createAndFolder(builder,bit, one, "bts-and");

        // Set the CF in EFLAGS/RFLAGS based on the extracted bit
        //Value* eflags = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
        setFlag(context, builder, FLAG_CF, bit);
        //SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, eflags);

        // Set the bit in the base operand
        Value* mask = builder.CreateShl(ConstantInt::get(baseVal->getType(), 1), bitOffsetMasked, "bts-shl");
        baseVal = createOrFolder(builder,baseVal, mask, "bts-or-" + to_string(instruction.runtime_address) + "-");
        SetOperandValue(context, builder, base, baseVal);
    }


    void lift_cwd(LLVMContext& context, IRBuilder<>& builder) {
        // Get the AX register value
        Value* ax = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AX), Type::getInt16Ty(context));

        // Right shift by 15 to isolate the sign bit of AX
        Value* signBit = builder.CreateAShr(ax, ConstantInt::get(Type::getInt16Ty(context), 15), "getSignBit");

        // If AX was positive or zero, signBit is now 0; if negative, signBit is now 1.
        // Use signBit to set DX to either 0x0000 (for 0) or 0xFFFF (for 1).
        Value* dx = createSelectFolder(builder,
            builder.CreateICmpEQ(signBit, ConstantInt::get(Type::getInt16Ty(context), 0)),
            ConstantInt::get(Type::getInt16Ty(context), 0),
            ConstantInt::get(Type::getInt16Ty(context), 0xFFFF),
            "setDX");

        // Store the result back to DX
        SetRegisterValue(context, builder, ZYDIS_REGISTER_DX, dx);
    }
    void lift_cqo(LLVMContext& context, IRBuilder<>& builder) {
        // Retrieve the RAX register's value
        Value* rax = GetRegisterValue(context, builder, ZYDIS_REGISTER_RAX);

        // Extract the sign bit (MSB) of RAX
        Value* msb = builder.CreateLShr( createZExtFolder(builder,rax,Type::getInt64Ty(context) ), 63, "cqo-msb");  // 63 for a 64-bit register
        Value* one = ConstantInt::get(msb->getType(), 1);
        msb = createAndFolder(builder,msb, one, "cqo-and");
        
        // If the MSB is 1, RDX will be all 1's, otherwise, all 0's.
        // This can be achieved by sign extending the MSB to 64 bits.
        Value* rdx = createSExtFolder(builder,msb, Type::getInt64Ty(context));

        // Update the RDX register with the computed value
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RDX, rdx);
    }


    void lift_cbw(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction) {
        // Assuming you have a method to get the AL register value
        Value* al = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AL), Type::getInt8Ty(context));

        // Sign extend AL to 16 bits (i.e., AX's size)
        Value* ax = createSExtFolder(builder,al, Type::getInt16Ty(context), "cbw");

        // Store the result back to AX
        SetRegisterValue(context, builder, ZYDIS_REGISTER_AX, ax);
    }

    void lift_cwde(LLVMContext& context, IRBuilder<>& builder) {
        // Get the AX register value
        Value* ax = builder.CreateTrunc(GetRegisterValue(context, builder, ZYDIS_REGISTER_AX), Type::getInt16Ty(context));

        // Sign extend AX to 32 bits (i.e., EAX's size)
        Value* eax = createSExtFolder(builder,ax, Type::getInt32Ty(context), "cwde");

        // Store the result back to EAX
        SetRegisterValue(context, builder, ZYDIS_REGISTER_EAX, eax);
    }

    void lift_cdqe(LLVMContext& context, IRBuilder<>& builder) {
        // Get the EAX register value
        Value* eax = createZExtOrTruncFolder(builder,GetRegisterValue(context, builder, ZYDIS_REGISTER_EAX), Type::getInt32Ty(context), "cdqe-trunc");

        // Sign extend EAX to 64 bits (i.e., RAX's size)
        Value* rax = createSExtFolder(builder,eax, Type::getInt64Ty(context), "cdqe");

        // Store the result back to RAX
        SetRegisterValue(context, builder, ZYDIS_REGISTER_RAX, rax);
    }

}




void liftInstruction(LLVMContext& context, IRBuilder<>& builder, ZydisDisassembledInstruction& instruction, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, bool* run) {


    // RIP gets updated before execution of the instruction.
    auto val = ConstantInt::getSigned(Type::getInt64Ty(context), instruction.runtime_address);
    SetRegisterValue(context, builder, ZYDIS_REGISTER_RIP, val);


    switch (instruction.info.mnemonic) {
        // movs
    case ZYDIS_MNEMONIC_MOVUPS:
    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD:
    case ZYDIS_MNEMONIC_MOV: {
        mov::lift_mov(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_MOVSB: {
        mov::lift_movsb(context, builder, instruction);
        break;
    }

    //cmov
    case ZYDIS_MNEMONIC_CMOVZ: {
        cmov::lift_cmovz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNZ: {
        cmov::lift_cmovnz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVL: {
        cmov::lift_cmovl(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVB: {
        cmov::lift_cmovb(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNB: {
        cmov::lift_cmovnb(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNS: {
        cmov::lift_cmovns(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_CMOVBE: {
        cmov::lift_cmovbz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNBE: {
        cmov::lift_cmovnbz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNL: {
        cmov::lift_cmovnl(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVS: {
        cmov::lift_cmovs(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNLE: {
        cmov::lift_cmovnle(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVLE: {
        cmov::lift_cmovle(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_CMOVO: {
        cmov::lift_cmovo(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNO: {
        cmov::lift_cmovno(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVP: {
        cmov::lift_cmovp(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMOVNP: {
        cmov::lift_cmovnp(context, builder, instruction);
        break;
    }
    // branches

    case ZYDIS_MNEMONIC_RET: // implement to check if its a real ret or not
    {
        branches::lift_ret(context, builder, instruction, blockAddresses, run);
        break; }

    case ZYDIS_MNEMONIC_JMP: {
        branches::lift_jmp(context, builder, instruction, blockAddresses, run);
        break;
    }

    case ZYDIS_MNEMONIC_JNZ: {
        branches::lift_jnz(context, builder, instruction, blockAddresses);
        break;
    }
    case ZYDIS_MNEMONIC_JZ: {
        branches::lift_jz(context, builder, instruction, blockAddresses);
        break;
    }    
    case ZYDIS_MNEMONIC_JS: {
        branches::lift_js(context, builder, instruction, blockAddresses);
        break;
    }    
    case ZYDIS_MNEMONIC_JNS: {
        branches::lift_jns(context, builder, instruction, blockAddresses);
        break;
    }
    case ZYDIS_MNEMONIC_JNBE: {

        branches::lift_jnbe(context, builder, instruction, blockAddresses);
        break;
    }       
    case ZYDIS_MNEMONIC_JNB: {
        branches::lift_jnb(context, builder, instruction, blockAddresses);
        break;
    }       
    case ZYDIS_MNEMONIC_JB: {
        branches::lift_jb(context, builder, instruction, blockAddresses);
        break;
    }   
    case ZYDIS_MNEMONIC_JBE: {

        branches::lift_jbe(context, builder, instruction, blockAddresses);
        break;
    }      
    case ZYDIS_MNEMONIC_JNLE: {
        branches::lift_jnle(context, builder, instruction, blockAddresses);
        break;
    }   
    case ZYDIS_MNEMONIC_JLE: {

        branches::lift_jle(context, builder, instruction, blockAddresses);
        break;
    }      
    case ZYDIS_MNEMONIC_JNL: {

        branches::lift_jnl(context, builder, instruction, blockAddresses);
        break;
    }      
    case ZYDIS_MNEMONIC_JL: {

        branches::lift_jl(context, builder, instruction, blockAddresses);
        break;
    }   
    case ZYDIS_MNEMONIC_JO: {

        branches::lift_jo(context, builder, instruction, blockAddresses);
        break;
    }    
    case ZYDIS_MNEMONIC_JNO: {

        branches::lift_jno(context, builder, instruction, blockAddresses);
        break;
    }   
    case ZYDIS_MNEMONIC_JP: {

        branches::lift_jp(context, builder, instruction, blockAddresses);
        break;
    }    
    case ZYDIS_MNEMONIC_JNP: {

        branches::lift_jnp(context, builder, instruction, blockAddresses);
        break;
    }
    // arithmetics and logical operations

    case ZYDIS_MNEMONIC_XCHG: {
        arithmeticsAndLogical::lift_xchg(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_NOT: {
        arithmeticsAndLogical::lift_not(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_BSWAP: {
        arithmeticsAndLogical::lift_bswap(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_NEG: {
        arithmeticsAndLogical::lift_neg(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SAR: {
        arithmeticsAndLogical::lift_sar(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_SHL: {
        arithmeticsAndLogical::lift_shl(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SHLD: {
        arithmeticsAndLogical::lift_shld(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SHRD: {
        arithmeticsAndLogical::lift_shrd(context, builder, instruction);
        break;

    }
    case ZYDIS_MNEMONIC_SHR: {
        arithmeticsAndLogical::lift_shr(context, builder, instruction);
        break;
    }
    
    case ZYDIS_MNEMONIC_RCR: {
        arithmeticsAndLogical::lift_rcr(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_RCL: {
        arithmeticsAndLogical::lift_rcl(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SBB: {
        arithmeticsAndLogical::lift_sbb(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_ADC: {
        arithmeticsAndLogical::lift_adc(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_XADD: {
        arithmeticsAndLogical::lift_xadd(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_LEA: {
        arithmeticsAndLogical::lift_lea(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_INC:
    case ZYDIS_MNEMONIC_DEC: {
        arithmeticsAndLogical::lift_inc_dec(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_IMUL: {
        arithmeticsAndLogical::lift_imul(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_IDIV: {
        arithmeticsAndLogical::lift_idiv(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_ADD: {
        arithmeticsAndLogical::lift_add_sub(context, builder, instruction);

        break;
    }

    case ZYDIS_MNEMONIC_XOR: {
        arithmeticsAndLogical::lift_xor(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_OR: {
        arithmeticsAndLogical::lift_or(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_AND: {
        arithmeticsAndLogical::lift_and(context, builder, instruction);

        break;
    }    
    case ZYDIS_MNEMONIC_ROR: {
        arithmeticsAndLogical::lift_ror(context, builder, instruction);

        break;
    }    
    case ZYDIS_MNEMONIC_ROL: {
        arithmeticsAndLogical::lift_rol(context, builder, instruction);

        break;
    }

    case ZYDIS_MNEMONIC_PUSH: {
        arithmeticsAndLogical::lift_push(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_PUSHFQ: {
        arithmeticsAndLogical::lift_pushfq(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_POP: {
        arithmeticsAndLogical::lift_pop(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_POPFQ: {
        arithmeticsAndLogical::lift_popfq(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_TEST: {
        arithmeticsAndLogical::lift_test(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMP: {
        arithmeticsAndLogical::lift_cmp(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_RDTSC: {
        arithmeticsAndLogical::lift_rdtsc(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_CALL: {
        branches::lift_call(context, builder, instruction, blockAddresses);
        break;
    }



    // set and flags
    case ZYDIS_MNEMONIC_SETZ: {
        flagOperation::lift_setz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNZ: {
        flagOperation::lift_setnz(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETO: {
        flagOperation::lift_seto(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNO: {
        flagOperation::lift_setno(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNB: {
        flagOperation::lift_setnb(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNBE: {
        flagOperation::lift_setnbe(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETBE: {
        flagOperation::lift_setbe(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNS: {
        flagOperation::lift_setns(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETP: {
        flagOperation::lift_setp(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNP: {
        flagOperation::lift_setnp(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETB: {
        flagOperation::lift_setb(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETS: {
        flagOperation::lift_sets(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNLE: {
        flagOperation::lift_setnle(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETLE: {
        flagOperation::lift_setle(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETNL: {
        flagOperation::lift_setnl(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_SETL: {
        flagOperation::lift_setl(context, builder, instruction);
        break;
    }

    case ZYDIS_MNEMONIC_BTR: {
        flagOperation::lift_btr(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_BSR: {
        flagOperation::lift_bsr(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_BSF: {
        flagOperation::lift_bsf(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_BTC: {
        flagOperation::lift_btc(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_LAHF: {
        flagOperation::lift_lahf(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_STC: {
        flagOperation::lift_stc(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CMC: {
        flagOperation::lift_cmc(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CLC: {
        flagOperation::lift_clc(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CLD: {
        flagOperation::lift_cld(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_CLI: {
        flagOperation::lift_cli(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_BTS: {
        flagOperation::lift_bts(context, builder, instruction);
        break;
    }
    case ZYDIS_MNEMONIC_BT: {
        flagOperation::lift_bt(context, builder, instruction);
        break;
    }
                          
    case ZYDIS_MNEMONIC_CDQ:
    {break; }
    case ZYDIS_MNEMONIC_CWDE: {
        flagOperation::lift_cwde(context, builder);
        break;
    }
    case ZYDIS_MNEMONIC_CWD: {
        flagOperation::lift_cwd(context, builder);
        break;
    }
    case ZYDIS_MNEMONIC_CQO: {
        flagOperation::lift_cqo(context, builder);
        break;
    }
    case ZYDIS_MNEMONIC_CDQE: {
        flagOperation::lift_cdqe(context, builder);
        break;
    }
    case ZYDIS_MNEMONIC_CBW:
    {
        flagOperation::lift_cbw(context, builder, instruction);
        break; }
   

    case ZYDIS_MNEMONIC_NOP: {
        break;
    }

    default: {
        cout << "not implemented: " << instruction.info.mnemonic << " runtime: " << hex << instruction.runtime_address << " " << instruction.text << "\n";
        throw std::runtime_error("not implemented");
        exit(-2);
    }
    }

}