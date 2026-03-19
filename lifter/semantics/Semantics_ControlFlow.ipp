// Semantics_ControlFlow.ipp — mov, cmov, call, ret, jmp, conditional branches
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_mov() {
  LLVMContext& context = builder->getContext();

  //  auto Rvalue2 =      GetIndexValue(src, src.size,
  //  std::to_string(current_address));
  auto Rvalue = GetIndexValue(1);

  printvalue(Rvalue);

  switch (instruction.mnemonic) {
  case Mnemonic::MOVSX: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVZX: {
    Rvalue = createZExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movzx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVSXD: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsxd-" + std::to_string(current_address) + "-");
    break;
  }
  default: {
    break;
  }
  }
  printvalue(Rvalue);

  switch (instruction.types[1]) {
  // case OperandType::Immediate64:
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])));
    break;
  }
  default:
    break;
  }

  printvalue(Rvalue);

  SetIndexValue(0, Rvalue);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmovcc() {

  auto getCondition = [&] {
    switch (instruction.mnemonic) {

    case Mnemonic::CMOVZ: {
      return getFlag(FLAG_ZF);
    }

    case Mnemonic::CMOVNZ: {
      return createNotFolder(getFlag(FLAG_ZF));
    }

    case Mnemonic::CMOVB: {
      return getFlag(FLAG_CF);
    }
    case Mnemonic::CMOVNB: {
      return createNotFolder(getFlag(FLAG_CF));
    }

    case Mnemonic::CMOVBE: {
      return createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNBE: {
      return createNotFolder(
          createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVL: {
      return createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF));
    }
    case Mnemonic::CMOVNL: {
      // equal
      return createNotFolder(
          createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)));
    }

    case Mnemonic::CMOVLE: {
      return createOrFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)),
                            getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNLE: {
      return createAndFolder(
          createNotFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF))),
          createNotFolder(getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVO: {
      return getFlag(FLAG_OF);
    }
    case Mnemonic::CMOVNO: {
      return createNotFolder(getFlag(FLAG_OF));
    }

    case Mnemonic::CMOVS: {
      return getFlag(FLAG_SF);
    }
    case Mnemonic::CMOVNS: {
      return createNotFolder(getFlag(FLAG_SF));
    }

    case Mnemonic::CMOVP: {
      return getFlag(FLAG_PF);
    }
    case Mnemonic::CMOVNP: {
      return createNotFolder(getFlag(FLAG_PF));
    }

    default: {
      return static_cast<Value*>(nullptr);
    }
    }
  };

  auto dest = GetIndexValue(0);

  auto src = GetIndexValue(1);

  auto result = createSelectFolder(getCondition(), src, dest);

  SetIndexValue(0, result);
}

// for now assume every call is fake
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_call() {
  LLVMContext& context = builder->getContext();

  // 0 = function
  // 1 = rip
  // 2 = register rsp
  // 3 = [rsp]
  /*
  auto src = operands[0];        // value that we are pushing
  auto rsp = operands[2];        // value that we are pushing
  auto rsp_memory = operands[3]; // value that we are pushing
  */
  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);

  auto result = createSubFolder(RspValue, val, "pushing_newrsp");

  uint64_t jump_address = current_address;

  std::string block_name = "jmp_call-" + std::to_string(jump_address) + "-";

  auto registerValue = GetIndexValue(0);
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16: // todo : pretty sure this 8 and 16 will cause
                                 // troubles later
  case OperandType::Immediate32:
  case OperandType::Immediate64: {

    // if (auto imm = dyn_cast<ConstantInt>(GetIndexValue(0))) {
    //   jump_address += imm->getSExtValue();
    //   break;
    // }
    // UNREACHABLE("wont reach");
    // break;
  }
  case OperandType::Memory8:
  case OperandType::Memory16: // todo : pretty sure this 8 and 16 will cause
                              // troubles later
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    registerValue =
        createAddFolder(registerValue, GetRegisterValue(Register::RIP));
    // auto registerValue = GetIndexValue(0);
    if (getControlFlow() == ControlFlow::Basic ||
        !isa<ConstantInt>(registerValue)) {

      std::cout << "did call";
      registerValue->print(outs());
      std::cout << "\n";
      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                          parseArgs(nullptr));

      break;
    }
    auto registerCValue = cast<ConstantInt>(registerValue);
    if (inlinePolicy.isOutline(registerCValue->getZExtValue())) {

      std::cout << "did call";
      registerValue->print(outs());
      std::cout << "\n";
      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                          parseArgs(nullptr));

      break;
    }
    jump_address = registerCValue->getZExtValue();
    break;
  }
  default:
    UNREACHABLE("unreachable in call");
    break;
  }

  // if inlining call
  // TODO:
  if (getControlFlow() == ControlFlow::Unflatten) {
    SetRegisterValue(Register::RSP, result);
    // // sub rsp 8 last,

    auto push_into_rsp = GetRegisterValue(Register::RIP);

    SetMemoryValue(getSPaddress(), push_into_rsp);
    // // sub rsp 8 last,

    auto bb = getOrCreateBB(jump_address, "bb_call");
    // if its trying to jump somewhere else than our binary, call it and
    // continue from [rsp]

    // // TODO: add some of this code to solvePath
    builder->CreateBr(bb);

    // printvalue2(jump_address);

    blockInfo = BBInfo(jump_address, bb);
    printvalue2("pushing block");
    addUnvisitedAddr(blockInfo);
    run = 0;
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_ret() { // fix
  LLVMContext& context = builder->getContext();
  // [0] = rip
  // [1] = rsp
  // [2] = [rsp]

  // if its ret 0x10
  // then its
  // [0] = 0x10
  // [1] = rip
  // [2] = rsp
  // [3] = [rsp]

  auto rspvalue = GetRegisterValue(Register::RSP);

  // IMPORTANT, change logic
  auto realval = GetMemoryValue(getSPaddress(), 64); // todo : based on bitness

  auto block = builder->GetInsertBlock();
  auto function = block->getParent();
  // auto lastinst = builder->CreateRet(realval);

  printvalue(rspvalue);

  // remov
  debugging::doIfDebug([&]() {
    std::string Filename = "output_rets.ll";
    std::error_code EC;
    raw_fd_ostream OS(Filename, EC);
    function->getParent()->print(OS, nullptr);
  });

  uint64_t destination = 0;

  uint8_t rop_result = REAL_return;

  if (llvm::ConstantInt* constInt =
          llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
    int64_t rspval = constInt->getSExtValue();
    printvalue2(rspval);
    rop_result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
  }
  printvalue2(rop_result);
  if (rop_result == REAL_return) {
    // lastinst->eraseFromParent();
    block->setName("real_return-" + std::to_string(current_address) + "-");

    auto rax = GetRegisterValue(Register::RAX);
    rax = createZExtFolder(
        rax, builder->getIntNTy(file.getMode() == arch_mode::X64 ? 64 : 32));
    // put this in a function
    // One entry per x64 GPR (RAX..R15).
    std::vector<llvm::Type*> argTypes(16, llvm::Type::getInt64Ty(context));
    auto myStructType = StructType::create(context, argTypes, "returnStruct");

    auto myStruct = UndefValue::get(myStructType);
    // Use CreateInsertValue for structs
    // auto returnvalue = builder->CreateInsertValue(myStruct, rax, {0});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RCX), {1});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RDX), {2});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RBX), {3});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RSP), {4});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RBP), {5});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RSI), {6});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::RDI), {7});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R8), {8});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R9), {9});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R10), {10});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R11), {11});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R12), {12});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R13), {13});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R14), {14});
    // returnvalue = builder->CreateInsertValue(
    //     returnvalue, GetRegisterValueWrapper(Register::R15), {15});
    builder->CreateRet(rax);
    Function* originalFunc_finalnopt = builder->GetInsertBlock()->getParent();

    run = 0;
    finished = 1;
    printvalue2(finished);
    return;
  }

  // lastinst->eraseFromParent();

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);
  auto rsp_result = createAddFolder(
      rspvalue, val, "ret-new-rsp-" + std::to_string(current_address) + "-");

  if (instruction.types[0] == OperandType::Immediate16) {

    rsp_result =
        createAddFolder(rsp_result, ConstantInt::get(rsp_result->getType(),
                                                     instruction.immediate));
  }

  SetRegisterValue(Register::RSP, rsp_result); // then add rsp 8

  auto pathResult = solvePath(function, destination, realval);
  if (pathResult == PATH_unsolved) {
    ++liftStats.blocks_unreachable;
    // ROP-style ret with non-constant target; log for triage
    std::cout << "[diag] lift_ret: unresolved ROP chain at 0x"
              << std::hex << (current_address - instruction.length)
              << std::dec << "\n" << std::flush;
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jmp() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];
  auto Value = GetIndexValue(0);
  auto ripval = GetRegisterValue(Register::RIP);
  Value = createSExtFolder(Value, ripval->getType());
  // TODO:
  // if its an imm, sext
  // if its r/m then we probably need to zext
  // auto newRip = createAddFolder(
  //    Value, ripval, "jump-xd-" + std::to_string(current_address) + "-");
  jmpcount++;
  auto targetv = Value;
  auto trunc = createSExtOrTruncFolder(targetv, Type::getInt64Ty(context),
                                       "jmp-register");
  printvalue(ripval);
  printvalue(trunc);
  uint64_t destination = 0;
  auto function = builder->GetInsertBlock()->getParent();
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16: // todo: test 8 and 16
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    trunc = createAddFolder(trunc, ripval);
    printvalue(trunc);
  }
  default:
    break;
  }
  auto pathResult = solvePath(function, destination, trunc);
  if (pathResult == PATH_unsolved) {
    ++liftStats.blocks_unreachable;
    // Indirect jump couldn't be resolved; likely CFF dispatch or computed target
    std::cout << "[diag] lift_jmp: unresolved indirect jump at 0x"
              << std::hex << (current_address - instruction.length)
              << std::dec << "\n" << std::flush;
  }
  printvalue2(destination);
  // printvalue(newRip);
  // SetRegisterValueWrapper(Register::RIP, newRip);
}

// jnz and jne
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnz() {

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  printvalue(zf);

  branchHelper(zf, "jnz", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_js() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "js");

  branchHelper(sf, "js", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jns() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jns");

  branchHelper(sf, "jns", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jz() {

  // if 0, then jmp, if not then not jump

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  branchHelper(zf, "jz", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jle", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jl");
  printvalue(sf);
  printvalue(of);
  auto condition = createXorFolder(sf, of, "jl_Condition");

  branchHelper(condition, "jl", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnl");

  printvalue(sf);
  printvalue(of);

  auto condition = createXorFolder(sf, of, "jl_condition");

  branchHelper(condition, "jnl", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jnle", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf) // auto dest = operands[0];

      // auto Value = GetIndexValue( dest, 64);
      // auto ripval = GetRegisterValue( Register::RIP);
      // auto newRip = createAddFolder( Value, ripval, "jbe");

      auto condition = createOrFolder(cf, zf, "jbe_Condition");

  branchHelper(condition, "jbe", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jb");

  auto condition = cf;
  branchHelper(condition, "jb", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnb");

  auto condition = cf;
  branchHelper(condition, "jnb", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf); // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jbe");

  auto condition = createOrFolder(cf, zf, "jnbe_Condition");

  branchHelper(condition, "jnbe", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jo() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jo");

  printvalue(of);
  branchHelper(of, "jo", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jno() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jno");

  branchHelper(of, "jno", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jp() {

  auto pf = getFlag(FLAG_PF);
  printvalue(pf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jp");

  branchHelper(pf, "jp", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnp() {

  auto pf = getFlag(FLAG_PF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnp");

  printvalue(pf);
  branchHelper(pf, "jnp", branchnumber, 1);

  branchnumber++;
}
