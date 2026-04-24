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

  // Provenance tagging: if this is `mov reg, [rip+disp]` and disp+RIP
  // resolves to an IAT slot, remember which import the register now holds.
  // A later `call reg` can then emit a named external call without needing
  // SSA-level back-tracing through the folded load.
  if (instruction.types[0] >= OperandType::Register8 &&
      instruction.types[0] <= OperandType::Register64 &&
      instruction.types[1] >= OperandType::Memory8 &&
      instruction.types[1] <= OperandType::Memory64 &&
      instruction.mem_base == Register::RIP &&
      instruction.mem_index == Register::None) {
    uint64_t ea = current_address + instruction.mem_disp;
    auto it = importMap.find(ea);
    if (it != importMap.end()) {
      registerImportSource[getBiggestEncoding(instruction.regs[0])] =
          it->second;
    }
  }
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

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);

  auto result = createSubFolder(RspValue, val, "pushing_newrsp");

  uint64_t jump_address = current_address;

  std::string block_name = "jmp_call-" + std::to_string(jump_address) + "-";

  // Track whether we emitted an external CreateCall (not inlineable).
  // When true, skip the Unflatten inlining path below.
  bool emittedExternalCall = false;

  // Fast path: detect `call [rip+disp]` (FF 15) direct IAT calls.
  // These are memory-operand calls where the effective address is an IAT slot.
  // Resolve the import name and emit a named function call without loading
  // the stale on-disk IAT value.
  if (instruction.types[0] >= OperandType::Memory8 &&
      instruction.types[0] <= OperandType::Memory64 &&
      instruction.mem_base == Register::RIP &&
      instruction.mem_index == Register::None) {
    // EA = RIP (post-instruction) + displacement.  current_address is already
    // advanced past the instruction, so it equals RIP at this point.
    uint64_t ea = current_address + instruction.mem_disp;
    auto it = importMap.find(ea);
    if (it != importMap.end()) {
      const auto& importName = it->second;
      callFunctionIR(importName, nullptr);
      debugging::doIfDebug([&]() {
        std::cout << "[call-abi] resolved import: " << importName << "\n"
                  << std::flush;
      });
      emittedExternalCall = true;

      // Skip the switch/Unflatten path entirely.
      goto call_done;
    }
    // Unresolved RIP-relative call: importMap has no entry for this IAT
    // slot.  Emit an opaque external call with strict-ABI clobber and
    // continue at the post-call address.  Falling through to operand
    // dispatch would treat the raw on-disk IAT bytes as a jump target
    // and silently corrupt the lift (the post-call block ends up
    // sealed with ret undef).
    {
      auto fx = this->buildUnknownCallFx();
      fx.target = CallTargetClass::UnknownIndirect;
      auto* eaValue = builder->getInt64(ea);
      auto* targetPtr = builder->CreateIntToPtr(
          eaValue, PointerType::get(context, 0));
      auto* callResult = builder->CreateCall(
          parseArgsType(nullptr, context), targetPtr, parseArgs(nullptr));
      applyPostCallEffects(callResult, fx);
      abi::printCallEffectsDiag(fx, current_address - instruction.length);
      diagnostics.warning(
          DiagCode::CallIndirectUnresolved,
          current_address - instruction.length,
          "Unresolved RIP-relative IAT call at EA=0x" +
              std::to_string(ea) + " (no importMap entry)");
      emittedExternalCall = true;
      goto call_done;
    }
  }

  // Provenance-based fast path for register-indirect calls.  If this
  // register was last loaded from an IAT slot, emit the named external
  // call directly — this covers the common MSVC pattern:
  //   mov rsi, [rip+iat]
  //   call rsi
  //   ... args setup ...
  //   call rsi
  // where the concolic engine has folded the load to a ConstantInt
  // matching the on-disk IAT value, losing SSA provenance.
  if (instruction.types[0] >= OperandType::Register8 &&
      instruction.types[0] <= OperandType::Register64) {
    Register reg = getBiggestEncoding(instruction.regs[0]);
    auto it = registerImportSource.find(reg);
    if (it != registerImportSource.end()) {
      const auto& importName = it->second;
      callFunctionIR(importName, nullptr);
      debugging::doIfDebug([&]() {
        std::cout << "[call-abi] resolved import via register provenance: "
                  << importName << "\n" << std::flush;
      });
      diagnostics.info(
          DiagCode::CallOutlinedImportThunk,
          current_address - instruction.length,
          "Resolved register-indirect import: " + importName);
      emittedExternalCall = true;
      goto call_done;
    }
  }

  { // Non-IAT call path: operand-based dispatch.
  auto registerValue = GetIndexValue(0);
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    // Fall through to register/memory handling.
  }
  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    registerValue =
        createAddFolder(registerValue, GetRegisterValue(Register::RIP));
    if (getControlFlow() == ControlFlow::Basic ||
        !isa<ConstantInt>(registerValue)) {

      // --- Emit external call (unknown/indirect target) ---
      auto fx = this->buildUnknownCallFx();
      fx.target = isa<ConstantInt>(registerValue)
                      ? CallTargetClass::UnknownDirect
                      : CallTargetClass::UnknownIndirect;

      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      auto callResult =
          builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                             parseArgs(nullptr));

      applyPostCallEffects(callResult, fx);
      abi::printCallEffectsDiag(fx, current_address - instruction.length);
      emittedExternalCall = true;
      break;
    }
    auto registerCValue = cast<ConstantInt>(registerValue);
    uint64_t rawTargetAddr = registerCValue->getZExtValue();
    uint64_t normalizedTargetAddr = normalizeRuntimeTargetAddress(rawTargetAddr);
    auto* normalizedTargetValue =
        builder->getIntN(registerCValue->getBitWidth(), normalizedTargetAddr);
    if ((inlinePolicy.isOutline(normalizedTargetAddr) ||
         shouldOutlineCall(normalizedTargetAddr)) &&
        !shouldInlineTinyOutlinedCall(normalizedTargetAddr)) {

      // --- Emit external call (outlined known-address target) ---
      auto importName = resolveImportName(normalizedTargetAddr);

      if (!importName.empty()) {
        // Named import: emit a proper LLVM function declaration.
        callFunctionIR(importName, nullptr);
        debugging::doIfDebug([&]() {
          std::cout << "[call-abi] resolved import: " << importName << "\n"
                    << std::flush;
        });
        diagnostics.info(DiagCode::CallOutlinedImportThunk,
                         current_address - instruction.length,
                         "Outlined import call: " + importName);
      } else {
        // Unknown outlined target: emit opaque inttoptr call.
        auto fx = this->buildUnknownCallFx();
        fx.target = CallTargetClass::UnknownDirect;

        auto idltvm = builder->CreateIntToPtr(
            normalizedTargetValue, PointerType::get(context, 0));
        auto callResult = builder->CreateCall(
            parseArgsType(nullptr, context), idltvm, parseArgs(nullptr));

        applyPostCallEffects(callResult, fx);
        abi::printCallEffectsDiag(fx, current_address - instruction.length);
        diagnostics.info(DiagCode::CallAbiApplied,
                         current_address - instruction.length,
                         "Outlined unknown-target call (inttoptr)");
      }
      emittedExternalCall = true;
      break;
    }
    jump_address = normalizedTargetAddr;
    break;
  }
  default:
    UNREACHABLE("unreachable in call");
    break;
  }

  // Unflatten inlining path: push return address to stack and branch to
  // the call target.  Skip this when we already emitted a CreateCall for
  // an external/indirect target — the call semantics are fully handled.
  if (!emittedExternalCall && getControlFlow() == ControlFlow::Unflatten) {

    // Speculative inlining: only start if enabled (maxCallInlineBudget > 0)
    // and not already inside a speculative inline.
    if (maxCallInlineBudget > 0 && !speculativeCall.active) {
      auto returnBB = getOrCreateBB(current_address, "call_return_cont");
      branch_backup(returnBB);

      speculativeCall.active        = true;
      speculativeCall.returnAddr    = current_address;
      speculativeCall.worklistFloor = unvisitedBlocks.size();
      speculativeCall.bailedOut     = false;
      speculativeCallBudget         = maxCallInlineBudget;
    }

    // Normal Unflatten path: push return address, branch to callee.
    SetRegisterValue(Register::RSP, result);

    auto push_into_rsp = GetRegisterValue(Register::RIP);

    SetMemoryValue(getSPaddress(), push_into_rsp);

    auto bb = getOrCreateBB(jump_address, "bb_call");

    branch_backup(bb);
    builder->CreateBr(bb);

    blockInfo = BBInfo(jump_address, bb);
    printvalue2("pushing block");
    addUnvisitedAddr(blockInfo);
    run = 0;
  }
  } // end non-IAT call path
call_done:;
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


  // --- ROP/continuation return: pop return address and adjust RSP ---
  const int ptrSize = (file.getMode() == arch_mode::X64) ? 8 : 4;
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), ptrSize);
  auto rsp_result = createAddFolder(
      rspvalue, val, "ret-new-rsp-" + std::to_string(current_address) + "-");

  // Handle `ret imm16` (callee-cleanup: stdcall, fastcall, or thunks).
  if (instruction.types[0] == OperandType::Immediate16) {
    rsp_result =
        createAddFolder(rsp_result, ConstantInt::get(rsp_result->getType(),
                                                     instruction.immediate));

    // Diagnostic: callee-cleanup detected via ret-immediate.
    const auto retCleanup =
        (getEffectiveAbi() == AbiKind::X86_STDCALL ||
         getEffectiveAbi() == AbiKind::X86_FASTCALL)
            ? StackCleanup::Callee
            : StackCleanup::Unknown;
    debugging::doIfDebug([&]() {
      std::cout << "[call-abi] ret imm=" << instruction.immediate
                << " cleanup=" << abi::stackCleanupName(retCleanup)
                << " at 0x" << std::hex
                << (current_address - instruction.length)
                << std::dec << "\n" << std::flush;
    });
  }

  SetRegisterValue(Register::RSP, rsp_result);

  // Ret-to-IAT import recognition.  If the value being popped resolves to
  // a concrete IAT slot, this ret is actually a 'push target; ret'
  // indirect-call gadget (VMP/Themida dispatcher idiom, or plain thunk).
  // Emit the named external call, then simulate the external's own ret by
  // popping the continuation address off the stack so control flow resumes
  // at the VM's post-call handler instead of lifting IAT bytes as code.
  //
  // Try two routes to a concrete target: direct ConstantInt (the popped
  // value was a SSA-folded load of an IAT slot) and computePossibleValues
  // returning a single concrete value (obfuscation chains that fold to one
  // address on this path).
  {
    uint64_t retTargetAddr = 0;
    bool retTargetResolved = false;
    if (auto* constInt = llvm::dyn_cast<llvm::ConstantInt>(realval)) {
      retTargetAddr = constInt->getZExtValue();
      retTargetResolved = true;
    } else {
      auto pvset = computePossibleValues(realval);
      if (pvset.size() == 1) {
        retTargetAddr = pvset.begin()->getZExtValue();
        retTargetResolved = true;
      }
    }
    if (retTargetResolved) {
      retTargetAddr = normalizeRuntimeTargetAddress(retTargetAddr);
      auto importIt = importMap.find(retTargetAddr);
      if (importIt != importMap.end()) {
        const auto& importName = importIt->second;
        callFunctionIR(importName, nullptr);
        diagnostics.info(
            DiagCode::CallOutlinedImportThunk,
            current_address - instruction.length,
            "Resolved ret-to-IAT import: " + importName);
        // Simulate the external callee's own ret by popping one more
        // qword (the continuation address pre-staged by the caller).
        // The new [rsp] now holds that continuation; feed it to solvePath
        // so the lifter continues at the VM's post-call handler instead
        // of the IAT pointer we just consumed.
        auto* continuationValue = GetMemoryValue(getSPaddress(), 64);
        rsp_result = createAddFolder(
            rsp_result,
            llvm::ConstantInt::get(rsp_result->getType(), ptrSize));
        SetRegisterValue(Register::RSP, rsp_result);
        realval = continuationValue;
      }
    }
  }
  
  ScopedPathSolveContext pathSolveContext(this, PathSolveContext::Ret);
  auto pathResult = solvePath(function, destination, realval);
  if (pathResult == PATH_unsolved) {
    ++liftStats.blocks_unreachable;
    uint64_t diagAddr = current_address - instruction.length;
    std::cout << "[diag] lift_ret: unresolved ROP chain at 0x"
              << std::hex << diagAddr << std::dec << "\n" << std::flush;
    diagnostics.warning(DiagCode::UnresolvedRetChain, diagAddr,
                        "Unresolved ROP chain (ret to symbolic address)");
  }

  // If the callee returned to our speculative call's return address,
  // the inline succeeded — deactivate the budget.
  if (speculativeCall.active && destination == speculativeCall.returnAddr) {
    speculativeCall.active = false;
    speculativeCallBudget = 0;
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
  const bool isDirectJump = instruction.types[0] == OperandType::Immediate8 ||
                            instruction.types[0] == OperandType::Immediate16 ||
                            instruction.types[0] == OperandType::Immediate32 ||
                            instruction.types[0] == OperandType::Immediate64;
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
  ScopedPathSolveContext pathSolveContext(
      this, isDirectJump ? PathSolveContext::DirectJump
                         : PathSolveContext::IndirectJump);
  auto pathResult = solvePath(function, destination, trunc);
  if (pathResult == PATH_unsolved) {
    ++liftStats.blocks_unreachable;
    uint64_t diagAddr = current_address - instruction.length;
    std::cout << "[diag] lift_jmp: unresolved indirect jump at 0x"
              << std::hex << diagAddr << std::dec << "\n" << std::flush;
    diagnostics.warning(DiagCode::UnresolvedIndirectJump, diagAddr,
                        "Unresolved indirect jump (symbolic target)");
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
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_loopx() {
  if (instruction.length != 2 || instruction.attributes != InstructionPrefix::None) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }


  const auto counterRegister =
      getRegOfSize(Register::RCX, file.getMode() == arch_mode::X64 ? 64 : 32);
  auto counterValue = GetRegisterValue(counterRegister);
  auto one = ConstantInt::get(counterValue->getType(), 1);
  auto decrementedCount =
      createSubFolder(counterValue, one, "loop-count-" + std::to_string(current_address));
  SetRegisterValue(counterRegister, decrementedCount);

  auto countNonZero = createICMPFolder(
      CmpInst::ICMP_NE, decrementedCount, ConstantInt::get(counterValue->getType(), 0),
      "loop-count-nonzero");

  Value* branchCondition = nullptr;
  switch (instruction.mnemonic) {
  case Mnemonic::LOOP:
    branchCondition = countNonZero;
    break;
  case Mnemonic::LOOPE:
    branchCondition = createAndFolder(countNonZero, getFlag(FLAG_ZF), "loope-cond");
    break;
  case Mnemonic::LOOPNE:
    branchCondition = createAndFolder(
        countNonZero, createNotFolder(getFlag(FLAG_ZF)), "loopne-cond");
    break;
  default:
    UNREACHABLE("unreachable mnemonic in lift_loopx");
  }

  branchHelper(branchCondition, "loop", branchnumber);
  branchnumber++;
}
