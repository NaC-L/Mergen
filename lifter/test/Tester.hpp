#pragma once

#include "LifterClass_Concolic.hpp"
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>

#include <cstdint>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using LifterUnderTest = lifterConcolic<>;
using RegisterUnderTest = std::remove_reference_t<
    decltype(std::declval<LifterUnderTest&>().instruction.regs[0])>;

struct RegisterState {
  RegisterUnderTest reg;
  llvm::APInt value;
};

struct FlagStatus {
  Flag flag;
  bool value;
};

struct InstructionTestCase {
  std::string name;
  std::vector<uint8_t> instructionBytes;
  std::vector<RegisterState> initialRegisters;
  std::vector<FlagStatus> initialFlags;
  std::vector<RegisterState> expectedRegisters;
  std::vector<FlagStatus> expectedFlags;
  std::optional<bool> expectedBranchTaken;  // for jcc tests
};

class InstructionTester {
public:
  int runAllTests(const std::vector<InstructionTestCase>& testCases,
                  const std::string& suiteFilter = "", bool checkFlags = false) {
    int failures = runCustomKnownBitsTests(suiteFilter);

    for (const auto& testCase : testCases) {
      if (!suiteFilter.empty() &&
          testCase.name.find(suiteFilter) == std::string::npos) {
        continue;
      }

      const bool ok = runTestCase(testCase, checkFlags);
      std::cout << "[" << (ok ? "  OK  " : " FAIL ") << "] " << testCase.name
                << "\n";
      failures += !ok;
    }

    if (failures == 0) {
      std::cout << "All instruction microtests passed" << std::endl;
    }

    return failures;
  }

private:
  static std::optional<llvm::APInt> readConstantAPInt(llvm::Value* value) {
    if (auto* constant = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      return constant->getValue();
    }
    return std::nullopt;
  }

  static std::string formatAPIntHex(const llvm::APInt& value) {
    llvm::SmallString<64> formatted;
    value.toString(formatted, 16, false);
    return "0x" + std::string(formatted);
  }

  static std::optional<bool> readConstantBool(llvm::Value* value) {
    if (auto* constant = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      return constant->getZExtValue() != 0;
    }
    return std::nullopt;
  }

  static bool shouldRunByFilter(const std::string& caseName,
                                const std::string& suiteFilter) {
    return suiteFilter.empty() ||
           caseName.find(suiteFilter) != std::string::npos;
  }

  static bool functionHasDirectCallTo(llvm::Function* function,
                                      llvm::StringRef calleeName) {
    for (auto& block : *function) {
      for (auto& instruction : block) {
        if (auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
          if (auto* callee = call->getCalledFunction();
              callee && callee->getName() == calleeName) {
            return true;
          }
        }
      }
    }
    return false;
  }

  static llvm::ConstantInt* makeI64(llvm::LLVMContext& context, uint64_t value) {
    return llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), value);
  }

  static void seedScasbState(LifterUnderTest& lifter, uint64_t addressValue,
                             uint8_t accumByte, uint8_t memoryByte,
                             uint64_t count = 1) {
    auto& context = lifter.builder->getContext();
    auto* address = makeI64(context, addressValue);
    lifter.SetRegisterValue(RegisterUnderTest::RDI, address);
    lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, accumByte));
    lifter.SetRegisterValue(RegisterUnderTest::RCX, makeI64(context, count));
    lifter.SetFlagValue_impl(FLAG_DF, lifter.builder->getFalse());
    lifter.SetMemoryValue(
        address, llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), memoryByte));
  }

  bool runKnownBitsI64ConstantCase(std::string& details) {
    LifterUnderTest lifter;
    auto* value = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(lifter.builder->getContext()), 0xF0ULL);
    auto knownBits = lifter.analyzeValueKnownBits(value, nullptr);

    if (!knownBits.isConstant()) {
      details = "  expected knownbits constant for i64 literal\n";
      return false;
    }

    const llvm::APInt expected(64, 0xF0ULL);
    if (knownBits.getConstant() != expected) {
      details = "  i64 knownbits mismatch: expected=" + formatAPIntHex(expected) +
                " actual=" + formatAPIntHex(knownBits.getConstant()) + "\n";
      return false;
    }

    return true;
  }

  bool runKnownBitsSimdFallbackCase(std::string& details) {
    LifterUnderTest lifter;
    const llvm::APInt xmmValue(128, "ffeeddccbbaa99887766554433221100", 16);
    auto* value = llvm::ConstantInt::get(lifter.builder->getContext(), xmmValue);
    auto knownBits = lifter.analyzeValueKnownBits(value, nullptr);

    const bool fallbackWidth = knownBits.getBitWidth() == 64;
    const bool fullyUnknown = knownBits.Zero.isZero() && knownBits.One.isZero() &&
                              !knownBits.hasConflict() && !knownBits.isConstant();
    if (!fallbackWidth || !fullyUnknown) {
      std::ostringstream oss;
      oss << "  expected unsupported SIMD knownbits fallback (unknown i64), got width="
          << knownBits.getBitWidth();
      if (knownBits.isConstant()) {
        oss << " constant=" << formatAPIntHex(knownBits.getConstant());
      }
      oss << "\n";
      details = oss.str();
      return false;
    }

    return true;
  }

  // ── Call-boundary ABI contract tests ──────────────────────────────
  //
  // These exercise the dual-mode (compat/strict) call effects directly.
  // We create a lifter, set a known value in a volatile register (R10),
  // simulate a post-call effect via applyPostCallEffects, and verify:
  //   compat → R10 keeps its value (no clobber)
  //   strict → R10 becomes undef (clobbered)

  bool runCallAbiCompatPreservesVolatile(std::string& details) {
    LifterUnderTest lifter;
    lifter.callModelMode = CallModelMode::Compat;

    // Set R10 to a known constant.
    const uint64_t r10_value = 0xCAFEBABE;
    lifter.SetRegisterValue(
        RegisterUnderTest::R10,
        llvm::ConstantInt::get(lifter.builder->getContext(),
                              llvm::APInt(64, r10_value)));

    // Simulate a call returning 0x1337.
    auto* callResult = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(lifter.builder->getContext()), 0x1337);
    auto fx = lifter.buildUnknownCallFx();
    lifter.applyPostCallEffects(callResult, fx);

    // In compat mode, R10 should still be the original constant.
    auto r10After = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::R10));
    if (!r10After.has_value()) {
      details = "  compat: R10 is not constant after call (expected preserved)\n";
      return false;
    }
    if (r10After->getZExtValue() != r10_value) {
      details = "  compat: R10 mismatch: expected=0xcafebabe actual=" +
                formatAPIntHex(*r10After) + "\n";
      return false;
    }

    // RAX should be the call result.
    auto raxAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::RAX));
    if (!raxAfter.has_value() || raxAfter->getZExtValue() != 0x1337) {
      details = "  compat: RAX not set to call result\n";
      return false;
    }
    return true;
  }

  bool runCallAbiStrictClobbersVolatile(std::string& details) {
    LifterUnderTest lifter;
    lifter.callModelMode = CallModelMode::Strict;

    // Set R10 to a known constant.
    lifter.SetRegisterValue(
        RegisterUnderTest::R10,
        llvm::ConstantInt::get(lifter.builder->getContext(),
                              llvm::APInt(64, 0xCAFEBABE)));
    // Set RBX (non-volatile) to a known constant.
    const uint64_t rbx_value = 0xDEADBEEF;
    lifter.SetRegisterValue(
        RegisterUnderTest::RBX,
        llvm::ConstantInt::get(lifter.builder->getContext(),
                              llvm::APInt(64, rbx_value)));

    // Simulate a call returning 0x1337.
    auto* callResult = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(lifter.builder->getContext()), 0x1337);
    auto fx = lifter.buildUnknownCallFx();
    lifter.applyPostCallEffects(callResult, fx);

    // In strict mode, R10 should be undef (not a constant).
    auto r10After = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::R10));
    if (r10After.has_value()) {
      details = "  strict: R10 is still constant (" +
                formatAPIntHex(*r10After) +
                ") but should be undef after clobber\n";
      return false;
    }

    // RBX (non-volatile) should still be preserved.
    auto rbxAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::RBX));
    if (!rbxAfter.has_value()) {
      details = "  strict: RBX is not constant (should survive as non-volatile)\n";
      return false;
    }
    if (rbxAfter->getZExtValue() != rbx_value) {
      details = "  strict: RBX mismatch: expected=0xdeadbeef actual=" +
                formatAPIntHex(*rbxAfter) + "\n";
      return false;
    }

    // RAX should be the call result (it's volatile but also the return reg).
    auto raxAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::RAX));
    if (!raxAfter.has_value() || raxAfter->getZExtValue() != 0x1337) {
      details = "  strict: RAX not set to call result\n";
      return false;
    }
    return true;
  }

  // Verify strict is the default — no explicit mode set.
  bool runCallAbiDefaultIsStrict(std::string& details) {
    LifterUnderTest lifter;
    // Do NOT set callModelMode — rely on the default.

    lifter.SetRegisterValue(
        RegisterUnderTest::R10,
        llvm::ConstantInt::get(lifter.builder->getContext(),
                              llvm::APInt(64, 0xCAFEBABE)));

    auto* callResult = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(lifter.builder->getContext()), 0x1337);
    auto fx = lifter.buildUnknownCallFx();
    lifter.applyPostCallEffects(callResult, fx);

    // R10 should be undef (default = strict = clobber volatile).
    auto r10After = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::R10));
    if (r10After.has_value()) {
      details = "  default mode: R10 is constant (" +
                formatAPIntHex(*r10After) +
                ") — expected undef (strict default)\n";
      return false;
    }
    return true;
  }

  bool runFunctionSignatureZeroArgPreserved(std::string& details) {
    using SignatureTable = funcsignatures<RegisterUnderTest>;
    auto* info = SignatureTable::getFunctionInfo(std::string("GetTickCount64"));
    if (!info) {
      details = "  missing GetTickCount64 signature info\n";
      return false;
    }
    if (!info->args.empty()) {
      details = "  GetTickCount64 arg count mismatch: expected=0 actual=" +
                std::to_string(info->args.size()) + "\n";
      return false;
    }
    return true;
  }

  bool runFunctionSignatureBinaryNameLookup(std::string& details) {
    using SignatureTable = funcsignatures<RegisterUnderTest>;
    auto* info = SignatureTable::getFunctionInfo(std::string("swprintf_s"));
    if (!info) {
      details = "  missing swprintf_s signature info\n";
      return false;
    }
    if (info->args.size() != 4) {
      details = "  swprintf_s arg count mismatch: expected=4 actual=" +
                std::to_string(info->args.size()) + "\n";
      return false;
    }
    if (info->args[0].reg != RegisterUnderTest::RCX ||
        info->args[1].reg != RegisterUnderTest::RDX ||
        info->args[2].reg != RegisterUnderTest::R8 ||
        info->args[3].reg != RegisterUnderTest::R9) {
      details = "  swprintf_s register order mismatch\n";
      return false;
    }
    return true;
  }

  bool runFunctionSignatureBinaryFallbackArgs(std::string& details) {
    using SignatureTable = funcsignatures<RegisterUnderTest>;
    auto* info = SignatureTable::getFunctionInfo(
        std::string("??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z"));
    if (!info) {
      details = "  missing ostream binary signature info\n";
      return false;
    }
    if (info->args.size() != 17) {
      details = "  ostream fallback arg count mismatch: expected=17 actual=" +
                std::to_string(info->args.size()) + "\n";
      return false;
    }
    return true;
  }


  bool runScasBasicPointerAdvance(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.builder->getContext();
    auto* address = makeI64(context, 0x2000);
    auto* value = makeI64(context, 0x4142434445464748ULL);
    lifter.SetRegisterValue(RegisterUnderTest::RDI, address);
    lifter.SetRegisterValue(RegisterUnderTest::RAX, value);
    lifter.SetFlagValue_impl(FLAG_DF, lifter.builder->getFalse());
    lifter.SetMemoryValue(address, value);

    static constexpr uint8_t kScasq[] = {0x48, 0xAF};
    lifter.liftBytes(kScasq, sizeof(kScasq));

    auto rdiAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::RDI));
    if (!rdiAfter.has_value() || rdiAfter->getZExtValue() != 0x2008) {
      details = "  SCASQ did not advance RDI by eight bytes\n";
      return false;
    }

    return true;
  }

  bool runScasRepeatPrefixesRejected(std::string& details) {
    auto checkRejected = [&](const std::string& name,
                             const std::vector<uint8_t>& instructionBytes) {
      LifterUnderTest lifter;
      seedScasbState(lifter, 0x2100, 0x41, 0x41, 3);
      lifter.liftBytes(instructionBytes.data(), instructionBytes.size());
      if (!functionHasDirectCallTo(lifter.fnc, "not_implemented")) {
        details += "  " + name + ": expected call to not_implemented\n";
        return false;
      }
      return true;
    };

    return checkRejected("repne scasb", std::vector<uint8_t>{0xF2, 0xAE}) &&
           checkRejected("repe scasb", std::vector<uint8_t>{0xF3, 0xAE});
  }

  bool runLoopAddressSizeOverrideRejected(std::string& details) {
    auto checkRejected = [&](const std::string& name,
                             const std::vector<uint8_t>& instructionBytes) {
      LifterUnderTest lifter;
      lifter.SetRegisterValue(RegisterUnderTest::RCX, makeI64(lifter.builder->getContext(), 2));
      lifter.liftBytes(instructionBytes.data(), instructionBytes.size());
      if (!functionHasDirectCallTo(lifter.fnc, "not_implemented")) {
        details += "  " + name + ": expected call to not_implemented\n";
        return false;
      }
      return true;
    };

    return checkRejected("addr32 loop", std::vector<uint8_t>{0x67, 0xE2, 0x10}) &&
           checkRejected("addr32 loope", std::vector<uint8_t>{0x67, 0xE1, 0x10}) &&
           checkRejected("addr32 loopne", std::vector<uint8_t>{0x67, 0xE0, 0x10});
  }


  bool runInt29FastfailLoweredToNoReturnCall(std::string& details) {
    LifterUnderTest lifter;
    lifter.SetRegisterValue(RegisterUnderTest::RCX,
                            makeI64(lifter.builder->getContext(), 0x42));
    static constexpr uint8_t kInt29[] = {0xCD, 0x29};
    lifter.liftBytes(kInt29, sizeof(kInt29));
    if (!functionHasDirectCallTo(lifter.fnc, "fastfail")) {
      details = "  int 29h should lower to a direct fastfail call\n";
      return false;
    }
    if (!llvm::isa<llvm::UnreachableInst>(lifter.bb->getTerminator())) {
      details = "  int 29h should terminate the block with unreachable\n";
      return false;
    }
    return true;
  }

  bool runXgetbvReturnsDeterministicXcr0(std::string& details) {
    LifterUnderTest lifter;
    lifter.SetRegisterValue(RegisterUnderTest::RCX,
                            makeI64(lifter.builder->getContext(), 0));
    static constexpr uint8_t kXgetbv[] = {0x0F, 0x01, 0xD0};
    lifter.liftBytes(kXgetbv, sizeof(kXgetbv));

    auto eaxAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::EAX));
    auto edxAfter = readConstantAPInt(
        lifter.GetRegisterValue(RegisterUnderTest::EDX));
    if (!eaxAfter.has_value() || eaxAfter->getZExtValue() != 0x7) {
      details = "  xgetbv should set EAX to modeled XCR0 low bits (0x7)\n";
      return false;
    }
    if (!edxAfter.has_value() || edxAfter->getZExtValue() != 0) {
      details = "  xgetbv should clear EDX for the modeled XCR0 high bits\n";
      return false;
    }
    return true;
  }

  bool runLoopGeneralizationConditionalBranchAllowed(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::ConditionalBranch;
    if (!lifter.currentPathSolveAllowsStructuredLoopGeneralization()) {
      details =
          "  conditional-branch loop context should allow structured loop-header reuse\n";
      return false;
    }
    return true;
  }

  bool runLoopGeneralizationDirectJumpAllowed(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext = LifterUnderTest::PathSolveContext::DirectJump;
    if (!lifter.currentPathSolveAllowsStructuredLoopGeneralization()) {
      details =
          "  direct-jump latch context should allow structured loop-header reuse\n";
      return false;
    }
    return true;
  }

  bool runLoopGeneralizationIndirectJumpBlockedWhenUnresolved(std::string& details) {
    // The unresolved-indirect-jump predicate must still exclude indirect
    // dispatchers from speculative loop generalization. Without a concrete
    // target, we have no proof the jump forms a backward loop edge.
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::IndirectJump;
    if (lifter.currentPathSolveAllowsStructuredLoopGeneralization()) {
      details =
          "  unresolved indirect-jump context must not generalize loop state\n";
      return false;
    }
    return true;
  }

  bool runLoopGeneralizationIndirectJumpAllowedWhenResolved(std::string& details) {
    // Once `solvePath` has pinned an indirect jump to a concrete destination,
    // the resolved-target predicate widens to admit it. Ret-path contexts
    // still have their own lifecycle and stay excluded.
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::IndirectJump;
    if (!lifter.currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget()) {
      details =
          "  resolved indirect-jump context must allow structured loop generalization\n";
      return false;
    }
    lifter.currentPathSolveContext = LifterUnderTest::PathSolveContext::Ret;
    if (lifter.currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget()) {
      details =
          "  ret context must never participate in structured loop generalization\n";
      return false;
    }
    return true;
  }

  bool runLoopGeneralizationRetBlocked(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext = LifterUnderTest::PathSolveContext::Ret;
    if (lifter.currentPathSolveAllowsStructuredLoopGeneralization()) {
      details = "  return-path loop context must not generalize loop state\n";
      return false;
    }
    return true;
  }

  bool runPendingGeneralizedLoopByContext(
      LifterUnderTest::PathSolveContext context, const char* contextName,
      bool expectReuse, std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext = context;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* pending =
        llvm::BasicBlock::Create(lifter.context, "pending_loop_header", lifter.fnc);
    lifter.builder->SetInsertPoint(current);
    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.addrToBB[0x1000] = pending;
    lifter.pendingLoopGeneralizationAddresses.insert(0x1000);

    uint64_t destination = 0;
    auto pathResult =
        lifter.solvePath(lifter.fnc, destination, makeI64(lifter.context, 0x1000));
    if (pathResult != PATH_solved || destination != 0x1000) {
      details = std::string("  ") + contextName +
                " context failed to solve the pending loop-header target\n";
      return false;
    }

    auto* branch = llvm::dyn_cast<llvm::BranchInst>(current->getTerminator());
    if (!branch || branch->getNumSuccessors() != 1) {
      details = std::string("  ") + contextName +
                " context did not emit the expected direct branch\n";
      return false;
    }
    const bool reused = branch->getSuccessor(0) == pending;
    if (expectReuse && !reused) {
      details = std::string("  ") + contextName +
                " context must reuse the pending generalized loop header when the target resolved concretely\n";
      return false;
    }
    if (!expectReuse && reused) {
      details = std::string("  ") + contextName +
                " context must not reuse a pending generalized loop header\n";
      return false;
    }
    if (!expectReuse && (lifter.unvisitedBlocks.empty() ||
                          lifter.unvisitedBlocks.back().block == pending)) {
      details = std::string("  ") + contextName +
                " context queued the pending generalized loop header instead of a fresh block\n";
      return false;
    }
    if (!lifter.pendingLoopGeneralizationAddresses.contains(0x1000)) {
      details = std::string("  ") + contextName +
                " context unexpectedly consumed the pending generalization state\n";
      return false;
    }
    return true;
  }

  bool runPendingGeneralizedLoopIndirectJumpAllowedWhenResolved(std::string& details) {
    // After the resolved-target relaxation, a constant-folded indirect-jump
    // target that matches a pending generalized loop header is reused just
    // like a direct-jump target would be.
    return runPendingGeneralizedLoopByContext(
        LifterUnderTest::PathSolveContext::IndirectJump, "indirect-jump",
        /*expectReuse=*/true, details);
  }

  bool runPendingGeneralizedLoopRetBlocked(std::string& details) {
    // Return-path contexts keep their own lifecycle — they must not reuse
    // pending generalized loop headers, even now that the resolved-target
    // relaxation admits indirect jumps.
    return runPendingGeneralizedLoopByContext(
        LifterUnderTest::PathSolveContext::Ret, "return-path",
        /*expectReuse=*/false, details);
  }


  bool runStructuredLoopHeaderAllowsConditionalBackedge(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::ConditionalBranch;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    auto* body = llvm::BasicBlock::Create(lifter.context, "loop_body", lifter.fnc);
    auto* exit = llvm::BasicBlock::Create(lifter.context, "loop_exit", lifter.fnc);

    llvm::IRBuilder<> currentBuilder(current);
    currentBuilder.CreateBr(header);

    llvm::IRBuilder<> headerBuilder(header);
    headerBuilder.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);

    llvm::IRBuilder<> bodyBuilder(body);
    bodyBuilder.CreateBr(current);

    llvm::IRBuilder<> exitBuilder(exit);
    exitBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.visitedAddresses.insert(0x1000);
    lifter.addrToBB[0x1000] = header;

    if (!lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
      details = "  visited conditional loop header should be eligible for structured reuse\n";
      return false;
    }
    return true;
  }

  bool runStructuredLoopHeaderAllowsJumpChain(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::DirectJump;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* trampoline =
        llvm::BasicBlock::Create(lifter.context, "loop_trampoline", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    auto* body = llvm::BasicBlock::Create(lifter.context, "loop_body", lifter.fnc);
    auto* exit = llvm::BasicBlock::Create(lifter.context, "loop_exit", lifter.fnc);

    llvm::IRBuilder<> currentBuilder(current);
    currentBuilder.CreateBr(trampoline);

    llvm::IRBuilder<> trampolineBuilder(trampoline);
    trampolineBuilder.CreateBr(header);

    llvm::IRBuilder<> headerBuilder(header);
    headerBuilder.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);

    llvm::IRBuilder<> bodyBuilder(body);
    bodyBuilder.CreateBr(current);

    llvm::IRBuilder<> exitBuilder(exit);
    exitBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.visitedAddresses.insert(0x1000);
    lifter.addrToBB[0x1000] = trampoline;

    if (!lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
      details =
          "  direct-jump trampoline chain into a conditional header should be eligible for structured reuse\n";
      return false;
    }
    return true;
  }


  bool runStructuredLoopHeaderRejectsNonConditionalTerminator(
      std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::ConditionalBranch;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    auto* exit = llvm::BasicBlock::Create(lifter.context, "loop_exit", lifter.fnc);

    llvm::IRBuilder<> currentBuilder(current);
    currentBuilder.CreateBr(header);

    llvm::IRBuilder<> headerBuilder(header);
    headerBuilder.CreateBr(exit);

    llvm::IRBuilder<> exitBuilder(exit);
    exitBuilder.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));

    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.visitedAddresses.insert(0x1000);
    lifter.addrToBB[0x1000] = header;

    if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
      details = "  non-conditional header must not be treated as a structured loop header\n";
      return false;
    }
    return true;
  }

  bool runStructuredLoopHeaderRejectsMultiplePredecessors(std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::ConditionalBranch;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* alternate = llvm::BasicBlock::Create(lifter.context, "alternate", lifter.fnc);
    auto* third = llvm::BasicBlock::Create(lifter.context, "third", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    auto* body = llvm::BasicBlock::Create(lifter.context, "loop_body", lifter.fnc);
    auto* exit = llvm::BasicBlock::Create(lifter.context, "loop_exit", lifter.fnc);

    llvm::IRBuilder<> currentBuilder(current);
    currentBuilder.CreateBr(header);

    llvm::IRBuilder<> alternateBuilder(alternate);
    alternateBuilder.CreateBr(header);

    llvm::IRBuilder<> thirdBuilder(third);
    thirdBuilder.CreateBr(header);

    llvm::IRBuilder<> headerBuilder(header);
    headerBuilder.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);

    llvm::IRBuilder<> bodyBuilder(body);
    bodyBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));

    llvm::IRBuilder<> exitBuilder(exit);
    exitBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.visitedAddresses.insert(0x1000);
    lifter.addrToBB[0x1000] = header;

    if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
      details =
          "  header with more than two predecessors must not be generalized as a structured loop\n";
      return false;
    }
    return true;
  }

  bool runStructuredLoopHeaderRejectsAcyclicBackwardBranch(
      std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::ConditionalBranch;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    auto* body = llvm::BasicBlock::Create(lifter.context, "loop_body", lifter.fnc);
    auto* exit = llvm::BasicBlock::Create(lifter.context, "loop_exit", lifter.fnc);

    llvm::IRBuilder<> currentBuilder(current);
    currentBuilder.CreateBr(header);

    llvm::IRBuilder<> headerBuilder(header);
    headerBuilder.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);

    llvm::IRBuilder<> bodyBuilder(body);
    bodyBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));

    llvm::IRBuilder<> exitBuilder(exit);
    exitBuilder.CreateRet(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.visitedAddresses.insert(0x1000);
    lifter.addrToBB[0x1000] = header;

    if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
      details =
          "  acyclic backward branch into an earlier conditional must not be generalized as a loop\n";
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopWithoutBypassTagKeepsNormalRestore(std::string& details) {
    LifterUnderTest lifter;
    auto* bb = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    BBInfo queued(0x1000, bb);
    lifter.pendingLoopGeneralizationAddresses.insert(0x1000);
    lifter.addUnvisitedAddr(queued);

    BBInfo out;
    if (!lifter.getUnvisitedAddr(out)) {
      details = "  failed to dequeue pending generalized loop header\n";
      return false;
    }
    if (lifter.bypassStackConcolicTracking) {
      details = "  generalized loop without bypass tag unexpectedly disabled concrete stack tracking\n";
      return false;
    }
    if (lifter.currentBlockRestoreMode != LifterUnderTest::BlockRestoreMode::Normal) {
      details = "  generalized loop without bypass tag should keep normal restore mode\n";
      return false;
    }
    if (!lifter.generalizedLoopAddresses.contains(0x1000)) {
      details = "  pending generalized loop header was not promoted after dequeue\n";
      return false;
    }
    return true;
  }

  bool runGeneralizedLoopWithBypassTagUsesGeneralizedRestore(std::string& details) {
    LifterUnderTest lifter;
    auto* bb = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    BBInfo queued(0x1000, bb);
    lifter.pendingLoopGeneralizationAddresses.insert(0x1000);
    lifter.stackBypassGeneralizedLoopAddresses.insert(0x1000);
    lifter.addUnvisitedAddr(queued);

    BBInfo out;
    if (!lifter.getUnvisitedAddr(out)) {
      details = "  failed to dequeue pending generalized loop header with bypass tag\n";
      return false;
    }
    if (!lifter.bypassStackConcolicTracking) {
      details = "  direct-jump generalized loop should enable stack-bypass restore mode\n";
      return false;
    }
    if (lifter.currentBlockRestoreMode != LifterUnderTest::BlockRestoreMode::GeneralizedLoop) {
      details = "  direct-jump generalized loop should use generalized restore mode\n";
      return false;
    }
    return true;
  }

  bool runGeneralizedLoopBypassTagClearsAfterPromotion(
      std::string& details) {
    LifterUnderTest lifter;
    auto* bb = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    lifter.pendingLoopGeneralizationAddresses.insert(0x1000);
    lifter.stackBypassGeneralizedLoopAddresses.insert(0x1000);
    lifter.addUnvisitedAddr(BBInfo(0x1000, bb));

    BBInfo out;
    if (!lifter.getUnvisitedAddr(out)) {
      details = "  failed to dequeue pending generalized loop header\n";
      return false;
    }
    if (!lifter.bypassStackConcolicTracking ||
        lifter.currentBlockRestoreMode !=
            LifterUnderTest::BlockRestoreMode::GeneralizedLoop) {
      details =
          "  pending direct-jump generalized loop should start in generalized restore mode\n";
      return false;
    }
    if (lifter.stackBypassGeneralizedLoopAddresses.contains(0x1000)) {
      details =
          "  pending bypass tag should be cleared once the generalized loop header is promoted\n";
      return false;
    }

    lifter.addUnvisitedAddr(BBInfo(0x1000, bb));
    if (!lifter.getUnvisitedAddr(out)) {
      details = "  failed to dequeue promoted generalized loop header\n";
      return false;
    }
    if (lifter.bypassStackConcolicTracking ||
        lifter.currentBlockRestoreMode !=
            LifterUnderTest::BlockRestoreMode::Normal) {
      details =
          "  promoted generalized loop should not keep the pending direct-jump bypass tag\n";
      return false;
    }
    return true;
  }

  bool runPromotedGeneralizedLoopRestoresCanonicalBackup(
      std::string& details) {
    LifterUnderTest lifter;
    lifter.currentPathSolveContext = LifterUnderTest::PathSolveContext::DirectJump;

    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    auto* bb = llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    lifter.builder->SetInsertPoint(current);
    lifter.blockInfo = BBInfo(0x2000, current);
    lifter.addrToBB[0x1000] = bb;
    lifter.pendingLoopGeneralizationAddresses.insert(0x1000);
    lifter.stackBypassGeneralizedLoopAddresses.insert(0x1000);

    const uint64_t localStackAddr = STACKP_VALUE - 0x20;
    const uint64_t nonLocalAddr = 0x500000;
    auto* localValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(lifter.context), 0xAA);
    auto* nonLocalValue =
        llvm::ConstantInt::get(llvm::Type::getInt8Ty(lifter.context), 0x55);
    lifter.buffer[localStackAddr] = ValueByteReference(localValue, 0);
    lifter.buffer[nonLocalAddr] = ValueByteReference(nonLocalValue, 0);

    uint64_t destination = 0;
    auto pathResult =
        lifter.solvePath(lifter.fnc, destination, makeI64(lifter.context, 0x1000));
    if (pathResult != PATH_solved || destination != 0x1000) {
      details =
          "  failed to queue the pending generalized loop header for backup-restore testing\n";
      return false;
    }

    BBInfo out;
    if (!lifter.getUnvisitedAddr(out) || out.block != bb) {
      details = "  failed to dequeue the pending generalized loop header\n";
      return false;
    }
    if (lifter.currentBlockRestoreMode !=
        LifterUnderTest::BlockRestoreMode::GeneralizedLoop) {
      details =
          "  pending direct-jump generalized loop should restore through generalized mode first\n";
      return false;
    }

    lifter.buffer.clear();
    lifter.load_generalized_backup(bb);
    if (lifter.buffer.contains(localStackAddr)) {
      details =
          "  generalized restore should drop stack-local backup entries while the pending bypass is active\n";
      return false;
    }
    if (!lifter.buffer.contains(nonLocalAddr)) {
      details =
          "  generalized restore should keep non-local backup entries while the pending bypass is active\n";
      return false;
    }

    lifter.addUnvisitedAddr(BBInfo(0x1000, bb));
    if (!lifter.getUnvisitedAddr(out) || out.block != bb) {
      details = "  failed to dequeue the promoted generalized loop header\n";
      return false;
    }
    if (lifter.currentBlockRestoreMode != LifterUnderTest::BlockRestoreMode::Normal) {
      details =
          "  promoted generalized loop should revert to normal restore mode before reloading the backup\n";
      return false;
    }

    lifter.buffer.clear();
    lifter.load_backup(bb);
    if (!lifter.buffer.contains(localStackAddr)) {
      details =
          "  promoted generalized loop did not restore the canonical stack-local backup contents\n";
      return false;
    }
    if (!lifter.buffer.contains(nonLocalAddr)) {
      details =
          "  promoted generalized loop lost non-local backup contents after restoring the canonical snapshot\n";
      return false;
    }
    return true;
  }



  bool runSolveLoadInfersConcreteBaseFromTrackedLoad(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i8Ty = llvm::Type::getInt8Ty(context);
    auto* i64Ty = llvm::Type::getInt64Ty(context);

    constexpr uint64_t baseSlot = STACKP_VALUE - 0x20;
    constexpr uint64_t indexSlot = STACKP_VALUE - 0x28;
    constexpr uint64_t tableBase = 0x14004DBECULL;
    constexpr uint64_t tableIndex = 4;
    constexpr uint64_t tableEntry = tableBase + tableIndex * 8;
    constexpr uint64_t tableTarget = 0x1401BAF04ULL;

    lifter.SetMemoryValue(makeI64(context, baseSlot), makeI64(context, tableBase));
    lifter.SetMemoryValue(makeI64(context, indexSlot), makeI64(context, tableIndex));
    lifter.SetMemoryValue(makeI64(context, tableEntry), makeI64(context, tableTarget));

    auto directBase =
        readConstantAPInt(lifter.GetMemoryValue(makeI64(context, baseSlot), 64));
    auto directIndex =
        readConstantAPInt(lifter.GetMemoryValue(makeI64(context, indexSlot), 64));
    if (!directBase.has_value() || !directIndex.has_value()) {
      std::ostringstream os;
      os << "  direct tracked loads did not resolve: base="
         << (directBase.has_value() ? std::to_string(directBase->getZExtValue())
                                    : std::string("<non-const>"))
         << " index="
         << (directIndex.has_value() ? std::to_string(directIndex->getZExtValue())
                                     : std::string("<non-const>")) << "\n";
      details = os.str();
      return false;
    }



    auto directTarget =
        readConstantAPInt(lifter.GetMemoryValue(makeI64(context, tableEntry), 64));
    if (!directTarget.has_value() || directTarget->getZExtValue() != tableTarget) {
      std::ostringstream os;
      os << "  direct table-entry load resolved to ";
      if (directTarget.has_value()) {
        os << "0x" << std::hex << directTarget->getZExtValue();
      } else {
        os << "<non-const>";
      }
      os << " instead of 0x" << std::hex << tableTarget << "\n";
      details = os.str();
      return false;
    }

    auto* basePtr = lifter.builder->CreateGEP(
        i8Ty, lifter.memoryAlloc, makeI64(context, baseSlot), "base_slot_ptr");
    auto* indexPtr = lifter.builder->CreateGEP(
        i8Ty, lifter.memoryAlloc, makeI64(context, indexSlot), "index_slot_ptr");

    auto* baseLoad = lifter.builder->CreateLoad(i64Ty, basePtr, "base_term");
    auto* indexLoad = lifter.builder->CreateLoad(i64Ty, indexPtr, "index_term");
    auto rawBaseValues = lifter.computePossibleValues(baseLoad, 0);
    auto rawIndexValues = lifter.computePossibleValues(indexLoad, 0);
    if (rawBaseValues.size() != 1 || rawIndexValues.size() != 1) {
      std::ostringstream os;
      os << "  computePossibleValues raw base/index sizes: "
         << rawBaseValues.size() << "/" << rawIndexValues.size() << "\n";
      details = os.str();
      return false;
    }

    auto* indexScaled =
        lifter.builder->CreateShl(indexLoad, makeI64(context, 3), "index_scaled");
    auto* tableAddr = lifter.builder->CreateAdd(baseLoad, indexScaled, "table_addr");
    auto tableAddrValues = lifter.computePossibleValues(tableAddr, 0);
    if (tableAddrValues.size() != 1 ||
        tableAddrValues.begin()->getZExtValue() != tableEntry) {
      std::ostringstream os;
      os << "  computePossibleValues tableAddr size/value: "
         << tableAddrValues.size();
      if (!tableAddrValues.empty()) {
        os << " / 0x" << std::hex << tableAddrValues.begin()->getZExtValue();
      }
      os << "\n";
      details = os.str();
      return false;
    }

    auto* probePtr = lifter.getPointer(tableAddr);
    LazyValue probeLoad([&]() -> llvm::Value* {
      return lifter.builder->CreateLoad(i64Ty, probePtr, "probe_load");
    });
    auto* directProbe = lifter.retrieveCombinedValue(tableEntry, 8, probeLoad);
    auto probeActual = readConstantAPInt(directProbe);
    if (!probeActual.has_value() || probeActual->getZExtValue() != tableTarget) {
      std::ostringstream os;
      os << "  direct retrieveCombinedValue probe resolved to ";
      if (probeActual.has_value()) {
        os << "0x" << std::hex << probeActual->getZExtValue();
      } else {
        std::string valueText;
        llvm::raw_string_ostream valueOs(valueText);
        directProbe->print(valueOs);
        os << valueOs.str();
      }
      os << " instead of 0x" << std::hex << tableTarget << "\n";
      details = os.str();
      return false;
    }

    auto* resolved = lifter.GetMemoryValue(tableAddr, 64);
    auto actual = readConstantAPInt(resolved);
    if (!actual.has_value()) {
      std::string valueText;
      llvm::raw_string_ostream os(valueText);
      resolved->print(os);
      details =
          "  solveLoad should resolve a jump-table address built from tracked base/index loads; got `" +
          os.str() + "`\n";
      return false;
    }
    if (actual->getZExtValue() != tableTarget) {
      std::ostringstream os;
      os << "  solveLoad resolved 0x" << std::hex << actual->getZExtValue()
         << " instead of expected jump-table target 0x" << tableTarget << "\n";
      details = os.str();
      return false;
    }
    return true;
  }


  bool runComputePossibleValuesEnumeratesPhiIncomings(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i64Ty = llvm::Type::getInt64Ty(context);

    // Four-way phi: verifies we don't accidentally cap at 2 (the byte-test
    // join test only exercises 2-way joins).
    auto* entry = llvm::BasicBlock::Create(context, "entry", lifter.fnc);
    auto* arm0 = llvm::BasicBlock::Create(context, "arm0", lifter.fnc);
    auto* arm1 = llvm::BasicBlock::Create(context, "arm1", lifter.fnc);
    auto* arm2 = llvm::BasicBlock::Create(context, "arm2", lifter.fnc);
    auto* arm3 = llvm::BasicBlock::Create(context, "arm3", lifter.fnc);
    auto* join = llvm::BasicBlock::Create(context, "join", lifter.fnc);

    llvm::IRBuilder<>(entry).CreateBr(arm0);
    llvm::IRBuilder<>(arm0).CreateBr(join);
    llvm::IRBuilder<>(arm1).CreateBr(join);
    llvm::IRBuilder<>(arm2).CreateBr(join);
    llvm::IRBuilder<>(arm3).CreateBr(join);

    lifter.builder->SetInsertPoint(join);
    llvm::IRBuilder<> phiBuilder(join, join->begin());
    auto* wide = phiBuilder.CreatePHI(i64Ty, 4, "wide_phi");
    const std::array<uint64_t, 4> widePayload = {
        0x00000000'DEADBEEFULL, 0x11111111'CAFEBABEULL,
        0x22222222'12345678ULL, 0x33333333'ABCDEF01ULL};
    wide->addIncoming(makeI64(context, widePayload[0]), arm0);
    wide->addIncoming(makeI64(context, widePayload[1]), arm1);
    wide->addIncoming(makeI64(context, widePayload[2]), arm2);
    wide->addIncoming(makeI64(context, widePayload[3]), arm3);

    auto wideValues = lifter.computePossibleValues(wide, 0);
    if (wideValues.size() != widePayload.size()) {
      std::ostringstream os;
      os << "  4-way phi should enumerate all four incomings, got size "
         << wideValues.size() << "\n";
      details = os.str();
      return false;
    }
    for (uint64_t want : widePayload) {
      if (!wideValues.contains(llvm::APInt(64, want))) {
        std::ostringstream os;
        os << "  4-way phi result missing 0x" << std::hex << want << "\n";
        details = os.str();
        return false;
      }
    }

    // Phi-of-phi: the outer phi's incoming is itself a phi.  The union must
    // recurse into the inner phi, not stop at it as a single 'unknown' operand.
    auto* innerArmA = llvm::BasicBlock::Create(context, "inner_a", lifter.fnc);
    auto* innerArmB = llvm::BasicBlock::Create(context, "inner_b", lifter.fnc);
    auto* innerJoin = llvm::BasicBlock::Create(context, "inner_join", lifter.fnc);
    auto* outerOther = llvm::BasicBlock::Create(context, "outer_other", lifter.fnc);
    auto* outerJoin = llvm::BasicBlock::Create(context, "outer_join", lifter.fnc);

    llvm::IRBuilder<>(innerArmA).CreateBr(innerJoin);
    llvm::IRBuilder<>(innerArmB).CreateBr(innerJoin);
    llvm::IRBuilder<>(innerJoin).CreateBr(outerJoin);
    llvm::IRBuilder<>(outerOther).CreateBr(outerJoin);

    llvm::IRBuilder<> innerPhiBuilder(innerJoin, innerJoin->begin());
    auto* innerPhi = innerPhiBuilder.CreatePHI(i64Ty, 2, "inner_phi");
    const uint64_t innerA = 0x10;
    const uint64_t innerB = 0x20;
    innerPhi->addIncoming(makeI64(context, innerA), innerArmA);
    innerPhi->addIncoming(makeI64(context, innerB), innerArmB);

    llvm::IRBuilder<> outerPhiBuilder(outerJoin, outerJoin->begin());
    auto* outerPhi = outerPhiBuilder.CreatePHI(i64Ty, 2, "outer_phi");
    const uint64_t outerOtherValue = 0x30;
    outerPhi->addIncoming(innerPhi, innerJoin);
    outerPhi->addIncoming(makeI64(context, outerOtherValue), outerOther);

    auto nestedValues = lifter.computePossibleValues(outerPhi, 0);
    const std::array<uint64_t, 3> nestedWant = {innerA, innerB, outerOtherValue};
    if (nestedValues.size() != nestedWant.size()) {
      std::ostringstream os;
      os << "  phi-of-phi should flatten to three leaf values, got size "
         << nestedValues.size() << "\n";
      details = os.str();
      return false;
    }
    for (uint64_t want : nestedWant) {
      if (!nestedValues.contains(llvm::APInt(64, want))) {
        std::ostringstream os;
        os << "  phi-of-phi result missing 0x" << std::hex << want << "\n";
        details = os.str();
        return false;
      }
    }
    return true;
  }


  bool runComputePossibleValuesCircularPhiBailsViaDepthGuard(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i64Ty = llvm::Type::getInt64Ty(context);

    // Build a two-block self-referential phi:
    //   header:  %self = phi i64 [ 0, %entry ], [ %self, %header ]
    //            br label %header
    // computePossibleValues must not infinite-loop on this shape.  The
    // existing Depth > 16 guard should trigger and return an empty set
    // (not hang, not crash).
    auto* entry = llvm::BasicBlock::Create(context, "entry", lifter.fnc);
    auto* header = llvm::BasicBlock::Create(context, "header", lifter.fnc);
    llvm::IRBuilder<>(entry).CreateBr(header);

    lifter.builder->SetInsertPoint(header);
    llvm::IRBuilder<> phiBuilder(header, header->begin());
    auto* selfPhi = phiBuilder.CreatePHI(i64Ty, 2, "self_referential_phi");
    selfPhi->addIncoming(makeI64(context, 0), entry);
    selfPhi->addIncoming(selfPhi, header);
    lifter.builder->CreateBr(header);

    auto values = lifter.computePossibleValues(selfPhi, 0);
    // Two reasonable outcomes are acceptable: the guard bails and returns an
    // empty set, or the handler dedupes the self-reference and returns just
    // {0}.  What is NOT acceptable is hanging or exploding the result set.
    if (values.size() > 1) {
      std::ostringstream os;
      os << "  circular phi should resolve to at most one unique value (0);"
         << " got size " << values.size() << "\n";
      details = os.str();
      return false;
    }
    if (values.size() == 1 &&
        !values.contains(llvm::APInt(64, 0))) {
      details =
          "  circular phi single-element result should be 0 (the entry incoming)\n";
      return false;
    }
    return true;
  }

  bool runComputePossibleValuesTruncToI1PreservesWidth(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i64Ty = llvm::Type::getInt64Ty(context);
    auto* entry = llvm::BasicBlock::Create(context, "entry", lifter.fnc);
    lifter.builder->SetInsertPoint(entry);

    // Even-low-bit vs odd-low-bit values, so trunc to i1 yields both 0 and 1.
    auto* cond = lifter.builder->CreateICmpEQ(
        lifter.GetRegisterValue(RegisterUnderTest::RAX),
        makeI64(context, 1), "trunc_i1_cond");
    auto* selected = lifter.builder->CreateSelect(
        cond, makeI64(context, 0xDEADBEEEULL), makeI64(context, 0xCAFEBABFULL),
        "trunc_i1_select");
    auto* truncI1 = lifter.builder->CreateTrunc(
        selected, llvm::Type::getInt1Ty(context), "trunc_i1_result");

    auto values = lifter.computePossibleValues(truncI1, 0);
    if (values.size() != 2) {
      std::ostringstream os;
      os << "  trunc to i1 should enumerate both {0, 1}, got size "
         << values.size() << "\n";
      details = os.str();
      return false;
    }
    for (const auto& value : values) {
      if (value.getBitWidth() != 1) {
        std::ostringstream os;
        os << "  trunc to i1 result width should be 1, got "
           << value.getBitWidth() << "\n";
        details = os.str();
        return false;
      }
    }
    (void)i64Ty;
    if (!values.contains(llvm::APInt(1, 0)) ||
        !values.contains(llvm::APInt(1, 1))) {
      details = "  trunc to i1 result should contain both 0 and 1\n";
      return false;
    }
    return true;
  }

  bool runComputePossibleValuesPreservesCastWidths(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* entry = llvm::BasicBlock::Create(context, "entry", lifter.fnc);
    lifter.builder->SetInsertPoint(entry);

    // Two i64 constants that differ in both halves, so a trunc to i32 yields
    // two distinct i32 values and a zext back to i64 would not recover the
    // high half.
    const uint64_t lhsValue = 0x00000001'DEADBEEFULL;
    const uint64_t rhsValue = 0x00000002'CAFEBABEULL;

    // A select over an unresolved condition gives computePossibleValues a
    // concrete two-element set to feed into the cast.
    auto* cond = lifter.builder->CreateICmpEQ(
        lifter.GetRegisterValue(RegisterUnderTest::RAX),
        makeI64(context, 1), "cast_width_cond");
    auto* selected = lifter.builder->CreateSelect(
        cond, makeI64(context, lhsValue), makeI64(context, rhsValue),
        "cast_width_select");

    auto* truncI32 = lifter.builder->CreateTrunc(
        selected, llvm::Type::getInt32Ty(context), "cast_width_trunc");
    auto truncValues = lifter.computePossibleValues(truncI32, 0);
    if (truncValues.size() != 2) {
      std::ostringstream os;
      os << "  trunc result should enumerate both low halves, got size "
         << truncValues.size() << "\n";
      details = os.str();
      return false;
    }
    for (const auto& value : truncValues) {
      if (value.getBitWidth() != 32) {
        std::ostringstream os;
        os << "  trunc result width should be 32, got " << value.getBitWidth()
           << "\n";
        details = os.str();
        return false;
      }
    }
    if (!truncValues.contains(llvm::APInt(32, static_cast<uint32_t>(lhsValue))) ||
        !truncValues.contains(llvm::APInt(32, static_cast<uint32_t>(rhsValue)))) {
      details =
          "  trunc result should contain both 32-bit low halves\n";
      return false;
    }

    auto* zextI64 = lifter.builder->CreateZExt(
        truncI32, llvm::Type::getInt64Ty(context), "cast_width_zext");
    auto zextValues = lifter.computePossibleValues(zextI64, 0);
    if (zextValues.size() != 2) {
      std::ostringstream os;
      os << "  zext result should enumerate both widened values, got size "
         << zextValues.size() << "\n";
      details = os.str();
      return false;
    }
    for (const auto& value : zextValues) {
      if (value.getBitWidth() != 64) {
        std::ostringstream os;
        os << "  zext result width should be 64, got " << value.getBitWidth()
           << "\n";
        details = os.str();
        return false;
      }
    }
    if (!zextValues.contains(llvm::APInt(64, static_cast<uint32_t>(lhsValue))) ||
        !zextValues.contains(llvm::APInt(64, static_cast<uint32_t>(rhsValue)))) {
      details =
          "  zext result should zero-extend both trunc halves back to 64 bits\n";
      return false;
    }

    auto* sextI64 = lifter.builder->CreateSExt(
        truncI32, llvm::Type::getInt64Ty(context), "cast_width_sext");
    auto sextValues = lifter.computePossibleValues(sextI64, 0);
    for (const auto& value : sextValues) {
      if (value.getBitWidth() != 64) {
        std::ostringstream os;
        os << "  sext result width should be 64, got " << value.getBitWidth()
           << "\n";
        details = os.str();
        return false;
      }
    }
    // 0xDEADBEEF has its high bit set, so SExt must produce 0xFFFFFFFF'DEADBEEF.
    if (!sextValues.contains(llvm::APInt(64, 0xFFFFFFFF'DEADBEEFULL))) {
      details =
          "  sext result should sign-extend the negative low half\n";
      return false;
    }
    return true;
  }


  bool runSolvePathSkipsRawZeroInMultiTargetSwitch(std::string& details) {
    LifterUnderTest lifter;
    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    lifter.builder->SetInsertPoint(current);
    lifter.blockInfo = BBInfo(0x1400237F9ULL, current);
    lifter.file.imageBase = 0x140000000ULL;
    lifter.markMemPaged(0x140020EADULL, 0x140020EB5ULL);
    lifter.markMemPaged(0x140023699ULL, 0x1400236A1ULL);
    // imageBase is intentionally mapped so that, if the raw-zero filter
    // regresses, the bug would surface as a bogus 0x140000000 switch case.
    lifter.markMemPaged(0x140000000ULL, 0x140000008ULL);
    lifter.currentPathSolveContext =
        LifterUnderTest::PathSolveContext::IndirectJump;

    auto* unknownCondA = lifter.builder->CreateICmpEQ(
        lifter.GetRegisterValue(RegisterUnderTest::RAX),
        makeI64(lifter.context, 1), "unknown_cond_a");
    auto* unknownCondB = lifter.builder->CreateICmpEQ(
        lifter.GetRegisterValue(RegisterUnderTest::RCX),
        makeI64(lifter.context, 2), "unknown_cond_b");
    auto* zeroOrMapped = lifter.builder->CreateSelect(
        unknownCondA, makeI64(lifter.context, 0),
        makeI64(lifter.context, 0x140020EADULL), "zero_or_mapped_select");
    auto* multiSelect = lifter.builder->CreateSelect(
        unknownCondB, zeroOrMapped,
        makeI64(lifter.context, 0x140023699ULL), "raw_zero_multi_select");

    uint64_t destination = 0;
    auto pathResult = lifter.solvePath(lifter.fnc, destination, multiSelect);
    if (pathResult != PATH_multi_solved || destination != 0) {
      std::ostringstream os;
      os << "  solvePath should emit a multi-target switch for {0, mapped, mapped}, got result="
         << pathResult << " dest=0x" << std::hex << destination << "\n";
      details = os.str();
      return false;
    }
    if (lifter.addrToBB.contains(0x140000000ULL)) {
      details =
          "  solvePath widened raw zero into an imageBase switch target\n";
      return false;
    }
    if (!lifter.addrToBB.contains(0x140020EADULL) ||
        !lifter.addrToBB.contains(0x140023699ULL)) {
      details =
          "  solvePath should still queue the mapped switch targets after filtering raw zero\n";
      return false;
    }
    return true;
  }

  bool runSolveLoadNormalizesMappedRvaCandidate(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;

    lifter.file.imageBase = 0x140000000ULL;
    constexpr uint64_t candidateRva = 0x8111ULL;
    constexpr uint64_t normalizedTarget = 0x140008111ULL;
    constexpr uint64_t loadedValue = 0x140188111ULL;

    lifter.markMemPaged(normalizedTarget, normalizedTarget + 8);
    lifter.SetMemoryValue(makeI64(context, normalizedTarget),
                          makeI64(context, loadedValue));

    auto* block = llvm::BasicBlock::Create(context, "current", lifter.fnc);
    lifter.builder->SetInsertPoint(block);
    lifter.blockInfo = BBInfo(0x1400237F9ULL, block);

    auto* candidateExpr = lifter.builder->CreateAdd(
        makeI64(context, candidateRva), makeI64(context, 0), "candidate_rva_expr");
    auto* resolved = lifter.GetMemoryValue(candidateExpr, 64);
    auto actual = readConstantAPInt(resolved);
    if (!actual.has_value() || actual->getZExtValue() != loadedValue) {
      std::ostringstream os;
      os << "  solveLoad should normalize mapped RVA candidate 0x" << std::hex
         << candidateRva << " to load 0x" << loadedValue << ", got ";
      if (actual.has_value()) {
        os << "0x" << actual->getZExtValue();
      } else {
        std::string valueText;
        llvm::raw_string_ostream valueOs(valueText);
        resolved->print(valueOs);
        os << '`' << valueOs.str() << '`';
      }
      os << "\n";
      details = os.str();
      return false;
    }
    return true;
  }

  bool runSolveLoadPhiAddressCreatesPhiOfLoadedValues(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i64Ty = llvm::Type::getInt64Ty(context);

    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* backedge = llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

    constexpr uint64_t stackSlotA = STACKP_VALUE;
    constexpr uint64_t stackSlotB = STACKP_VALUE + 8;
    constexpr uint64_t valueA = 0x1111111111111111ULL;
    constexpr uint64_t valueB = 0x2222222222222222ULL;

    lifter.builder->SetInsertPoint(preheader);
    lifter.SetMemoryValue(makeI64(context, stackSlotA), makeI64(context, valueA));

    lifter.builder->SetInsertPoint(backedge);
    lifter.SetMemoryValue(makeI64(context, stackSlotB), makeI64(context, valueB));

    lifter.builder->SetInsertPoint(loopHeader);
    auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "stack_slot_addr_phi");
    addressPhi->addIncoming(makeI64(context, stackSlotA), preheader);
    addressPhi->addIncoming(makeI64(context, stackSlotB), backedge);

    auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
    if (!phi) {
      std::string valueText;
      llvm::raw_string_ostream os(valueText);
      resolved->print(os);
      details =
          "  solveLoad should turn a PHI of concrete addresses into a PHI of the loaded values; got `" +
          os.str() + "`\n";
      return false;
    }
    if (phi->getParent() != loopHeader) {
      details =
          "  solveLoad PHI-address result should live in the same header block as the address PHI\n";
      return false;
    }

    bool sawA = false;
    bool sawB = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto actual = readConstantAPInt(phi->getIncomingValue(i));
      if (!actual.has_value()) {
        details =
            "  solveLoad PHI-address incoming loads should stay concrete for this test\n";
        return false;
      }
      if (incomingBlock == preheader && actual->getZExtValue() == valueA) {
        sawA = true;
      }
      if (incomingBlock == backedge && actual->getZExtValue() == valueB) {
        sawB = true;
      }
    }

    if (!sawA || !sawB) {
      details =
          "  solveLoad PHI-address result should preserve both incoming concrete stack-slot values\n";
      return false;
    }
    return true;
  }


bool runSolveLoadPhiAddressWithDisplacementCreatesPhiOfLoadedValues(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);

  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge = llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t stackSlotA = STACKP_VALUE;
  constexpr uint64_t stackSlotB = STACKP_VALUE + 8;
  constexpr uint64_t valueA = 0x1111111111111111ULL;
  constexpr uint64_t valueB = 0x2222222222222222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, stackSlotA + 6), makeI64(context, valueA));

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, stackSlotB + 6), makeI64(context, valueB));

  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "stack_slot_addr_phi");
  addressPhi->addIncoming(makeI64(context, stackSlotA), preheader);
  addressPhi->addIncoming(makeI64(context, stackSlotB), backedge);
  auto* displacedAddress = lifter.builder->CreateAdd(
      addressPhi, llvm::ConstantInt::get(i64Ty, 6),
      "stack_slot_addr_phi_plus_6");

  auto* resolved = lifter.GetMemoryValue(displacedAddress, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    std::string valueText;
    llvm::raw_string_ostream os(valueText);
    resolved->print(os);
    details =
        "  solveLoad should turn a displaced PHI of concrete addresses into a PHI of the loaded values; got `" +
        os.str() + "`\n";
    return false;
  }
  if (phi->getParent() != loopHeader) {
    details =
        "  solveLoad displaced PHI-address result should live in the same header block as the address PHI\n";
    return false;
  }

  bool sawA = false;
  bool sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto* incomingBlock = phi->getIncomingBlock(i);
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) {
      details =
          "  solveLoad displaced PHI-address incoming loads should stay concrete for this test\n";
      return false;
    }
    if (incomingBlock == preheader && actual->getZExtValue() == valueA) {
      sawA = true;
    }
    if (incomingBlock == backedge && actual->getZExtValue() == valueB) {
      sawB = true;
    }
  }

  if (!sawA || !sawB) {
    details =
        "  solveLoad displaced PHI-address result should preserve both incoming concrete stack-slot values\n";
    return false;
  }
  return true;
}


// Multi-way backedges (>=3 paths into the same header).
//
// branch_backup(bb, /*generalized=*/true) appends each distinct backedge
// snapshot to generalizedLoopBackedgeBackup[bb] (dedup by sourceBlock).
// load_generalized_backup then builds (1 + N)-incoming phis carrying
// canonical + every backedge. The two tests below exercise the N-way
// contract end-to-end at N=3.
bool runGeneralizedLoopThirdBackedgePreservesAllThreeSnapshots(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* thirdBackedge =
      llvm::BasicBlock::Create(context, "third_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint64_t thirdControl = 0x1401AEC37ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(secondBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, secondControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(thirdBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, thirdControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  auto it = lifter.generalizedLoopBackedgeBackup.find(loopHeader);
  if (it == lifter.generalizedLoopBackedgeBackup.end()) {
    details = "  generalizedLoopBackedgeBackup[loopHeader] missing after "
              "three generalized branch_backup calls\n";
    return false;
  }
  // All three backedge snapshots must survive in the vector, one per
  // distinct sourceBlock; earlier calls must not be overwritten.
  if (it->second.size() != 3) {
    std::ostringstream os;
    os << "  generalizedLoopBackedgeBackup[loopHeader] size="
       << it->second.size() << ", expected 3 (one per distinct backedge)\n";
    details = os.str();
    return false;
  }
  bool sawFirst = false, sawSecond = false, sawThird = false;
  for (const auto& be : it->second) {
    if (be.sourceBlock == firstBackedge) sawFirst = true;
    else if (be.sourceBlock == secondBackedge) sawSecond = true;
    else if (be.sourceBlock == thirdBackedge) sawThird = true;
  }
  if (!sawFirst || !sawSecond || !sawThird) {
    details =
        "  generalizedLoopBackedgeBackup should hold one entry for each of "
        "firstBackedge, secondBackedge, thirdBackedge\n";
    return false;
  }
  return true;
}

bool runGeneralizedLoopLoadBackupWithThreeBackedgesProducesFourWayPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* thirdBackedge =
      llvm::BasicBlock::Create(context, "third_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint64_t thirdControl = 0x1401AEC37ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(secondBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, secondControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(thirdBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, thirdControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlPhiValue =
      lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(controlPhiValue);
  if (!phi) {
    details = "  control-slot load at header should produce a phi under "
              "generalized loop mode\n";
    return false;
  }
  // 1 canonical + 3 backedges = 4 incomings.
  if (phi->getNumIncomingValues() != 4) {
    std::ostringstream os;
    os << "  control-slot phi carries " << phi->getNumIncomingValues()
       << " incomings, expected 4 (canonical + three backedges)\n";
    details = os.str();
    return false;
  }
  bool sawCanonical = false;
  bool sawFirst = false;
  bool sawSecond = false;
  bool sawThird = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalControl) sawCanonical = true;
    else if (v == firstControl) sawFirst = true;
    else if (v == secondControl) sawSecond = true;
    else if (v == thirdControl) sawThird = true;
  }
  if (!sawCanonical || !sawFirst || !sawSecond || !sawThird) {
    details =
        "  control-slot phi should carry canonicalControl, firstControl, "
        "secondControl, and thirdControl as concrete incomings\n";
    return false;
  }
  return true;
}

// KNOWN-LIMITATION (non-Themida control slot is invisible to generalization).
//
// retrieve_generalized_loop_control_slot_value_impl explicitly gates on
// `startAddress != this->kThemidaControlCursorSlot` and returns nullptr for
// every other address. A loop whose control cursor is stored at any address
// other than 0x14004DD19 does not get its load re-routed through the
// canonical/backedge phi; the caller falls back to the normal memory
// pipeline, which yields a concrete or last-written value - not a phi.
//
// When the hardcoded slot is replaced with per-function detection or a
// tagging layer, this test MUST fail and be rewritten to assert the new
// discovery mechanism.
bool runGeneralizedLoopNonThemidaControlSlotProducesNoPhi(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t themidaControlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  // A plausible control-cursor slot for a different protected binary.
  // Not 0x14004DD19, so the slot-value retrieval must bail.
  constexpr uint64_t otherControlSlot = 0x140050000ULL;
  constexpr uint64_t otherCanonicalValue = 0x1100220033004400ULL;
  constexpr uint64_t otherBackedgeValue = 0x5500660077008800ULL;

  lifter.builder->SetInsertPoint(preheader);
  // Themida slot - required to activate the generalized state machinery.
  lifter.SetMemoryValue(makeI64(context, themidaControlSlot),
                        makeI64(context, canonicalControl));
  // The actual slot under test, seeded with distinct canonical value.
  lifter.SetMemoryValue(makeI64(context, otherControlSlot),
                        makeI64(context, otherCanonicalValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, themidaControlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, otherControlSlot),
                        makeI64(context, otherBackedgeValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* loadedAtOtherSlot =
      lifter.GetMemoryValue(makeI64(context, otherControlSlot), 64);
  if (llvm::isa<llvm::PHINode>(loadedAtOtherSlot)) {
    details = "  GetMemoryValue at non-Themida control slot unexpectedly "
              "produced a PHINode - the hardcoded slot gate has been "
              "generalized; rewrite this test against the new contract.\n";
    return false;
  }
  return true;
}

// KNOWN-LIMITATION (nested loops share a single active state slot).
//
// activeGeneralizedLoopControlFieldState is a scalar struct, not a stack.
// load_generalized_backup(bb) calls clearGeneralizedLoopControlFieldState()
// at entry and then re-populates the scalar from BBbackup[bb] and
// generalizedLoopBackedgeBackup[bb]. An inner loop that calls
// load_generalized_backup while an outer loop's state is active
// overwrites the outer scalar. At any instant, only one header's state
// is queryable through the retrieve_generalized_loop_* helpers.
//
// (The per-header archive in generalizedLoopControlFieldStates is
// populated on every successful load, not only on
// record_generalized_loop_backedge, so the archive is a cache - not a
// nesting stack. Lifting nested loops today requires the caller to
// manually reload whichever header's state it needs next.)
//
// When nested-loop support lands (state stack, or lazy per-header lookup
// within the retrieve_generalized_loop_* helpers), this test MUST fail
// and be rewritten against the new nesting contract.
bool runGeneralizedLoopNestedInnerOverwritesOuterActiveState(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* outerPreheader =
      llvm::BasicBlock::Create(context, "outer_preheader", lifter.fnc);
  auto* outerBackedge =
      llvm::BasicBlock::Create(context, "outer_backedge", lifter.fnc);
  auto* outerHeader =
      llvm::BasicBlock::Create(context, "outer_header", lifter.fnc);
  auto* innerPreheader =
      llvm::BasicBlock::Create(context, "inner_preheader", lifter.fnc);
  auto* innerBackedge =
      llvm::BasicBlock::Create(context, "inner_backedge", lifter.fnc);
  auto* innerHeader =
      llvm::BasicBlock::Create(context, "inner_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t outerCanonicalControl = 0x1401AF740ULL;
  constexpr uint64_t outerBackedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t innerCanonicalControl = 0x1401BA72CULL;
  constexpr uint64_t innerBackedgeControl = 0x1401BA97FULL;

  // Outer loop setup.
  lifter.builder->SetInsertPoint(outerPreheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, outerCanonicalControl));
  lifter.branch_backup(outerHeader);
  lifter.builder->SetInsertPoint(outerBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, outerBackedgeControl));
  lifter.branch_backup(outerHeader, /*generalized=*/true);
  lifter.load_generalized_backup(outerHeader);
  if (!lifter.activeGeneralizedLoopControlFieldState.valid ||
      lifter.activeGeneralizedLoopControlFieldState.headerBlock != outerHeader) {
    details = "  outer load_generalized_backup failed to activate outer state\n";
    return false;
  }

  // Inner loop setup (nested inside outer, outer not yet promoted).
  lifter.builder->SetInsertPoint(innerPreheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, innerCanonicalControl));
  lifter.branch_backup(innerHeader);
  lifter.builder->SetInsertPoint(innerBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, innerBackedgeControl));
  lifter.branch_backup(innerHeader, /*generalized=*/true);
  lifter.load_generalized_backup(innerHeader);

  // Active state is now inner's; outer's active state was overwritten.
  if (lifter.activeGeneralizedLoopControlFieldState.headerBlock != innerHeader) {
    details = "  inner load_generalized_backup failed to activate inner state\n";
    return false;
  }
  return true;
}

bool runSolvePathResolvesGeneralizedPhiLoadTarget(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);
  auto* loopBody =
      llvm::BasicBlock::Create(context, "loop_body", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint16_t backedgeField = 0xB174U;
  constexpr uint16_t secondField = 0x812FU;
  constexpr int32_t backedgeDisp = -1459;
  constexpr int32_t secondDisp = -1337;
  constexpr uint32_t seed32 = 0x5F514EADU;
  constexpr uint32_t add32 = 165327398U;
  constexpr uint64_t tableBase = 5370313337ULL;
  constexpr uint64_t resolvedTarget = 0x140020EADULL;

  auto computeExpectedTableAddress = [&](uint16_t field) -> uint64_t {
    const uint32_t mixed = seed32 ^ static_cast<uint32_t>(field);
    const uint32_t biased = mixed + add32;
    const uint64_t masked = static_cast<uint64_t>(biased) & 0xFFFFULL;
    return tableBase + (masked << 3);
  };
  const uint64_t tableAddrA = computeExpectedTableAddress(backedgeField);
  const uint64_t tableAddrB = computeExpectedTableAddress(secondField);

  lifter.markMemPaged(resolvedTarget, resolvedTarget + 8);
  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               backedgeDisp));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               backedgeField));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlValue = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* displacedAddress = lifter.builder->CreateAdd(
      controlValue, llvm::ConstantInt::get(controlValue->getType(), 6),
      "generalized_control_slot_plus_6_solvepath");
  auto* dispValue = lifter.GetMemoryValue(displacedAddress, 32);

  lifter.builder->SetInsertPoint(loopBody);
  auto* recurrentControl = lifter.builder->CreateAdd(
      controlValue,
      lifter.builder->CreateSExtOrTrunc(dispValue, llvm::Type::getInt64Ty(context)),
      "rolled_control_state_solvepath");
  lifter.SetMemoryValue(makeI64(context, controlSlot), recurrentControl);
  lifter.SetMemoryValue(makeI64(context, secondControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               secondDisp));
  lifter.SetMemoryValue(makeI64(context, secondControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               secondField));
  lifter.record_generalized_loop_backedge(loopHeader);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  lifter.blockInfo = BBInfo(0x1400237F9ULL, loopHeader);
  lifter.current_address = 0x1400237F9ULL;
  llvm::IRBuilder<> phiBuilder(loopHeader, loopHeader->begin());
  auto* controlPhi = phiBuilder.CreatePHI(llvm::Type::getInt64Ty(context), 2,
                                          "rolled_control_phi_for_solvepath");
  controlPhi->addIncoming(makeI64(context, backedgeControl), firstBackedge);
  controlPhi->addIncoming(makeI64(context, secondControl), loopBody);
  auto* displacedControl = lifter.builder->CreateAdd(
      controlPhi, llvm::ConstantInt::get(controlPhi->getType(), 0xC),
      "rolled_generalized_phi_address_plus_12_solvepath");
  auto* fieldValue = lifter.GetMemoryValue(displacedControl, 16);
  auto* field32 = lifter.builder->CreateTruncOrBitCast(
      lifter.builder->CreateZExt(fieldValue, llvm::Type::getInt64Ty(context)),
      llvm::Type::getInt32Ty(context));
  auto* mixed = lifter.builder->CreateXor(
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), seed32), field32,
      "rolled_solvepath_mixed");
  auto* biased = lifter.builder->CreateAdd(
      mixed, llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), add32),
      "rolled_solvepath_biased");
  auto* masked = lifter.builder->CreateAnd(
      lifter.builder->CreateZExt(biased, llvm::Type::getInt64Ty(context)),
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0xFFFFULL),
      "rolled_solvepath_masked");
  auto* scaled = lifter.builder->CreateShl(
      masked, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 3),
      "rolled_solvepath_scaled");
  auto* tableAddr = lifter.builder->CreateAdd(
      scaled, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), tableBase),
      "rolled_solvepath_table_addr");

  lifter.SetMemoryValue(makeI64(context, tableAddrA), makeI64(context, resolvedTarget));
  lifter.SetMemoryValue(makeI64(context, tableAddrB), makeI64(context, resolvedTarget));
  auto* pointer = lifter.getPointer(tableAddr);
  auto* load = lifter.builder->CreateLoad(llvm::Type::getInt64Ty(context), pointer,
                                          "generalized_phi_load_target");
  auto loadValues = lifter.computePossibleValues(load, 0);
  if (loadValues.size() != 1 ||
      !loadValues.contains(llvm::APInt(64, resolvedTarget))) {
    std::ostringstream os;
    os << "  generalized phi-address load should enumerate one concrete target before solvePath, got size "
       << loadValues.size();
    for (const auto& value : loadValues) {
      os << " 0x" << std::hex << value.getZExtValue();
    }
    os << "\n";
    details = os.str();
    return false;
  }

  LifterUnderTest::ScopedPathSolveContext pathSolveContext(
      &lifter, LifterUnderTest::PathSolveContext::IndirectJump);
  uint64_t destination = 0;
  auto pathResult = lifter.solvePath(lifter.fnc, destination, load);
  if (pathResult != PATH_solved || destination != resolvedTarget) {
    std::ostringstream os;
    os << "  solvePath should resolve the rolled generalized load target to 0x"
       << std::hex << resolvedTarget << ", got result=" << pathResult
       << " dest=0x" << destination << "\n";
    details = os.str();
    return false;
  }
  return true;
}

  bool runGeneralizedLoopLocalPhiAddressCreatesPhiOfLoadedValues(
      std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* i64Ty = llvm::Type::getInt64Ty(context);

    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* backedge = llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

    constexpr uint64_t controlSlot = 0x14004DD19ULL;
    constexpr uint64_t canonicalControl = 0x1401AF740ULL;
    constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
    constexpr uint64_t localSlotA = STACKP_VALUE;
    constexpr uint64_t localSlotB = STACKP_VALUE + 8;
    constexpr uint64_t valueA = 0x1111111111111111ULL;
    constexpr uint64_t valueB = 0x2222222222222222ULL;

    lifter.builder->SetInsertPoint(preheader);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, canonicalControl));
    lifter.SetMemoryValue(makeI64(context, localSlotA), makeI64(context, valueA));
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(backedge);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, backedgeControl));
    lifter.SetMemoryValue(makeI64(context, localSlotB), makeI64(context, valueB));
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    lifter.builder->SetInsertPoint(loopHeader);
    auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "generalized_stack_slot_phi");
    addressPhi->addIncoming(makeI64(context, localSlotA), preheader);
    addressPhi->addIncoming(makeI64(context, localSlotB), backedge);

    auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
    if (!phi) {
      std::string valueText;
      llvm::raw_string_ostream os(valueText);
      resolved->print(os);
      details =
          "  generalized loop local PHI-address load should produce a phi of the incoming local values; got `" +
          os.str() + "`\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto actual = readConstantAPInt(phi->getIncomingValue(i));
      if (!actual.has_value()) {
        details =
            "  generalized loop local PHI-address incoming values should stay concrete in the focused test\n";
        return false;
      }
      if (incomingBlock == preheader && actual->getZExtValue() == valueA) {
        sawCanonical = true;
      }
      if (incomingBlock == backedge && actual->getZExtValue() == valueB) {
        sawBackedge = true;
      }
    }
    if (!sawCanonical || !sawBackedge) {
      details =
          "  generalized loop local PHI-address result should preserve both incoming local snapshot values\n";
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopControlFieldLoadCreatesPhi(std::string& details) {
    constexpr std::array<uint64_t, 3> fieldOffsets = {0x6ULL, 0xAULL, 0xCULL};
    constexpr std::array<uint16_t, 3> canonicalFields = {0x11, 0x22, 0x33};
    constexpr std::array<uint16_t, 3> backedgeFields = {0x44, 0x55, 0x66};

    for (size_t caseIndex = 0; caseIndex < fieldOffsets.size(); ++caseIndex) {
      LifterUnderTest lifter;
      auto& context = lifter.context;
      auto* i8Ty = llvm::Type::getInt8Ty(context);
      auto* i16Ty = llvm::Type::getInt16Ty(context);
      auto* i64Ty = llvm::Type::getInt64Ty(context);

      auto* preheader =
          llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
      auto* backedge = llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
      auto* loopHeader =
          llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

      constexpr uint64_t controlSlot = 0x14004DD19ULL;
      constexpr uint64_t canonicalControl = 0x1401AF740ULL;
      constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
      const uint64_t fieldOffset = fieldOffsets[caseIndex];
      const uint16_t canonicalField = canonicalFields[caseIndex];
      const uint16_t backedgeField = backedgeFields[caseIndex];

      lifter.builder->SetInsertPoint(preheader);
      lifter.SetMemoryValue(makeI64(context, canonicalControl + fieldOffset),
                            llvm::ConstantInt::get(i16Ty, canonicalField));
      lifter.SetMemoryValue(makeI64(context, controlSlot),
                            makeI64(context, canonicalControl));
      lifter.branch_backup(loopHeader);

      lifter.builder->SetInsertPoint(backedge);
      lifter.SetMemoryValue(makeI64(context, backedgeControl + fieldOffset),
                            llvm::ConstantInt::get(i16Ty, backedgeField));
      lifter.SetMemoryValue(makeI64(context, controlSlot),
                            makeI64(context, backedgeControl));
      lifter.branch_backup(loopHeader, /*generalized=*/true);

      lifter.load_generalized_backup(loopHeader);
      lifter.builder->SetInsertPoint(loopHeader);

      auto* controlSlotPtr = lifter.builder->CreateGEP(
          i8Ty, lifter.memoryAlloc, makeI64(context, controlSlot),
          "control_slot_ptr");
      auto* controlLoad =
          lifter.builder->CreateLoad(i64Ty, controlSlotPtr, "control_cursor");
      auto* fieldAddress = lifter.builder->CreateAdd(
          controlLoad, makeI64(context, fieldOffset), "control_field_addr");
      auto* resolved = lifter.GetMemoryValue(fieldAddress, 16);
      auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
      if (!phi) {
        std::string valueText;
        llvm::raw_string_ostream os(valueText);
        resolved->print(os);
        std::ostringstream detailsStream;
        detailsStream
            << "  generalized loop control-derived field load at offset 0x"
            << std::hex << fieldOffset << " should produce a phi, got `"
            << os.str() << "`\n";
        details = detailsStream.str();
        return false;
      }
      if (phi->getParent() != loopHeader) {
        std::ostringstream detailsStream;
        detailsStream
            << "  generalized loop control-field phi at offset 0x" << std::hex
            << fieldOffset
            << " should be anchored in the generalized header block\n";
        details = detailsStream.str();
        return false;
      }

      bool sawCanonical = false;
      bool sawBackedge = false;
      for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
        auto* incomingBlock = phi->getIncomingBlock(i);
        auto actual = readConstantAPInt(phi->getIncomingValue(i));
        if (!actual.has_value()) {
          std::ostringstream detailsStream;
          detailsStream
              << "  generalized loop control-field phi incoming value at offset 0x"
              << std::hex << fieldOffset << " should stay concrete\n";
          details = detailsStream.str();
          return false;
        }
        if (incomingBlock == preheader &&
            actual->getZExtValue() == canonicalField) {
          sawCanonical = true;
        }
        if (incomingBlock == backedge &&
            actual->getZExtValue() == backedgeField) {
          sawBackedge = true;
        }
      }

      if (!sawCanonical || !sawBackedge) {
        std::ostringstream detailsStream;
        detailsStream
            << "  generalized loop control-field phi at offset 0x" << std::hex
            << fieldOffset
            << " should merge canonical and backedge field bytes\n";
        details = detailsStream.str();
        return false;
      }
    }
    return true;
  }


  bool runSolvePathWidensMappedRvaTarget(std::string& details) {
    LifterUnderTest lifter;
    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    lifter.builder->SetInsertPoint(current);
    lifter.blockInfo = BBInfo(0x1401BAF5DULL, current);
    lifter.file.imageBase = 0x140000000ULL;
    lifter.markMemPaged(0x1400118C8ULL, 0x1400118D0ULL);

    uint64_t destination = 0;
    auto pathResult =
        lifter.solvePath(lifter.fnc, destination, makeI64(lifter.context, 0x118C8));
    if (pathResult != PATH_solved) {
      details = "  solvePath did not resolve the mapped RVA-style target\n";
      return false;
    }
    if (destination != 0x1400118C8ULL) {
      std::ostringstream os;
      os << "  solvePath widened to 0x" << std::hex << destination
         << " instead of mapped RVA target 0x1400118c8\n";
      details = os.str();
      return false;
    }
    return true;
  }

  bool runSolvePathPrefersMappedTargetOverNullForIndirectJump(std::string& details) {
    LifterUnderTest lifter;
    auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
    lifter.builder->SetInsertPoint(current);
    lifter.blockInfo = BBInfo(0x1400237F9ULL, current);
    lifter.markMemPaged(0x140020EADULL, 0x140020EB5ULL);

    LifterUnderTest::ScopedPathSolveContext pathSolveContext(
        &lifter, LifterUnderTest::PathSolveContext::IndirectJump);
    uint64_t destination = 0;
    auto* selectValue = lifter.builder->CreateSelect(
        lifter.builder->getInt1(true),
        makeI64(lifter.context, 0x140020EADULL),
        makeI64(lifter.context, 0),
        "indirect_target_select");
    auto pathResult = lifter.solvePath(lifter.fnc, destination, selectValue);
    if (pathResult != PATH_solved || destination != 0x140020EADULL) {
      std::ostringstream os;
      os << "  solvePath should prefer the mapped indirect target 0x140020ead over null, got result="
         << pathResult << " dest=0x" << std::hex << destination << "\n";
      details = os.str();
      return false;
    }
    return true;
  }


  bool runTinyOutlinedCallBypassesOutlinePolicy(std::string& details) {
    LifterUnderTest lifter;
    lifter.markMemPaged(0x140001518ULL, 0x140001608ULL);
    lifter.inlinePolicy.addAddress(0x140001518ULL);
    lifter.inlinePolicy.addAddress(0x140001554ULL);
    lifter.inlinePolicy.addAddress(0x140001600ULL);
    if (!lifter.shouldInlineTinyOutlinedCall(0x140001518ULL)) {
      details =
          "  tiny outlined helper should bypass outline policy\n";
      return false;
    }
    if (lifter.shouldInlineTinyOutlinedCall(0x140001554ULL)) {
      details =
          "  outlined helper with next entry beyond the tiny threshold must not bypass outline policy\n";
      return false;
    }
    return true;
  }

  bool runNormalizeRuntimeTargetWidensMappedRvaTarget(std::string& details) {
    LifterUnderTest lifter;
    lifter.file.imageBase = 0x140000000ULL;
    lifter.markMemPaged(0x140052532ULL, 0x140052540ULL);
    const uint64_t normalized = lifter.normalizeRuntimeTargetAddress(0x52532ULL);
    if (normalized != 0x140052532ULL) {
      std::ostringstream os;
      os << "  normalizeRuntimeTargetAddress widened to 0x" << std::hex
         << normalized << " instead of mapped RVA target 0x140052532\n";
      details = os.str();
      return false;
    }
    return true;
  }








  bool runSetRegisterValueZeroExtends32BitWrites(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;

    lifter.SetRegisterValue(RegisterUnderTest::RCX,
                            makeI64(context, 0xFFFF'FFFF'1234'5678ULL));
    lifter.SetRegisterValue(RegisterUnderTest::ECX,
                            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                                   0x89ABCDEFu));

    auto actual = readConstantAPInt(lifter.GetRegisterValue(RegisterUnderTest::RCX));
    if (!actual.has_value()) {
      details =
          "  writing ECX should leave RCX concrete and zero-extended\n";
      return false;
    }
    if (actual->getZExtValue() != 0x89ABCDEFULL) {
      std::ostringstream os;
      os << "  writing ECX should zero-extend RCX to 0x89ABCDEF, got 0x"
         << std::hex << actual->getZExtValue() << "\n";
      details = os.str();
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopControlSlotCreatesPhi(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

    constexpr uint64_t controlSlot = 0x14004DD19ULL;
    constexpr uint64_t canonicalControl = 0x1401AF740ULL;
    constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

    lifter.builder->SetInsertPoint(preheader);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, canonicalControl));
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(firstBackedge);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, backedgeControl));
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    lifter.builder->SetInsertPoint(loopHeader);
    auto* resolved = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
    if (!phi) {
      details =
          "  generalized control slot should resolve through a phi when canonical and backedge controls differ\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto actual = readConstantAPInt(phi->getIncomingValue(i));
      if (!actual.has_value()) {
        details =
            "  generalized control slot phi incoming values should stay concrete in the focused test\n";
        return false;
      }
      if (incomingBlock == preheader &&
          actual->getZExtValue() == canonicalControl) {
        sawCanonical = true;
      }
      if (incomingBlock == firstBackedge &&
          actual->getZExtValue() == backedgeControl) {
        sawBackedge = true;
      }
    }
    if (!sawCanonical || !sawBackedge) {
      details =
          "  generalized control slot phi should preserve both canonical and backedge controls\n";
      return false;
    }
    return true;
  }

  bool runGeneralizedLoopControlSlotDisplacementCreatesPhiOfLoadedValues(
      std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

    constexpr uint64_t controlSlot = 0x14004DD19ULL;
    constexpr uint64_t canonicalControl = 0x1401AF740ULL;
    constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
    constexpr int32_t canonicalDisp = -1610;
    constexpr int32_t backedgeDisp = -1459;

    lifter.builder->SetInsertPoint(preheader);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, canonicalControl));
    lifter.SetMemoryValue(makeI64(context, canonicalControl + 0x6),
                          llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                                 canonicalDisp));
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(firstBackedge);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, backedgeControl));
    lifter.SetMemoryValue(makeI64(context, backedgeControl + 0x6),
                          llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                                 backedgeDisp));
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    lifter.builder->SetInsertPoint(loopHeader);
    auto* controlValue = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
    auto* displacedAddress = lifter.builder->CreateAdd(
        controlValue, llvm::ConstantInt::get(controlValue->getType(), 6),
        "generalized_control_slot_plus_6");
    auto* resolved = lifter.GetMemoryValue(displacedAddress, 32);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
    if (!phi || phi->getNumIncomingValues() != 2) {
      details =
          "  generalized control-slot displacement load should resolve through a 2-way phi\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto actual = readConstantAPInt(phi->getIncomingValue(i));
      if (!actual.has_value()) {
        details =
            "  generalized control-slot displacement phi incoming values should stay concrete\n";
        return false;
      }
      if (incomingBlock == preheader &&
          actual->getSExtValue() == canonicalDisp) {
        sawCanonical = true;
      }
      if (incomingBlock == firstBackedge &&
          actual->getSExtValue() == backedgeDisp) {
        sawBackedge = true;
      }
    }
    if (!sawCanonical || !sawBackedge) {
      details =
          "  generalized control-slot displacement phi should preserve both canonical and backedge loads\n";
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopTargetSlotCreatesPhi(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

    constexpr uint64_t controlSlot = 0x14004DD19ULL;
    constexpr uint64_t targetSlot = 0x14004DC67ULL;
    constexpr uint64_t canonicalControl = 0x1401AF740ULL;
    constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
    constexpr uint64_t canonicalValue = 0x1111222233334444ULL;
    constexpr uint64_t backedgeValue = 0xAAAABBBBCCCCDDDDULL;

    lifter.builder->SetInsertPoint(preheader);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, canonicalControl));
    lifter.SetMemoryValue(makeI64(context, targetSlot),
                          makeI64(context, canonicalValue));
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(firstBackedge);
    lifter.SetMemoryValue(makeI64(context, controlSlot),
                          makeI64(context, backedgeControl));
    lifter.SetMemoryValue(makeI64(context, targetSlot),
                          makeI64(context, backedgeValue));
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    lifter.builder->SetInsertPoint(loopHeader);
    auto* resolved = lifter.GetMemoryValue(makeI64(context, targetSlot), 64);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
    if (!phi) {
      details =
          "  generalized target slot should resolve through a phi when canonical and backedge values differ\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto actual = readConstantAPInt(phi->getIncomingValue(i));
      if (!actual.has_value()) {
        details =
            "  generalized target slot phi incoming values should stay concrete in the focused test\n";
        return false;
      }
      if (incomingBlock == preheader &&
          actual->getZExtValue() == canonicalValue) {
        sawCanonical = true;
      }
      if (incomingBlock == firstBackedge &&
          actual->getZExtValue() == backedgeValue) {
        sawBackedge = true;
      }
    }
    if (!sawCanonical || !sawBackedge) {
      details =
          "  generalized target slot phi should preserve both canonical and backedge values\n";
      return false;
    }
    return true;
  }



bool runRolledGeneralizedPhiAddressUsesAdvancedPair(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);
  auto* loopBody =
      llvm::BasicBlock::Create(context, "loop_body", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint16_t backedgeField = 0xB174U;
  constexpr uint16_t secondField = 0x812F;
  constexpr int32_t backedgeDisp = -1459;
  constexpr int32_t secondDisp = -1337;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               backedgeDisp));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               backedgeField));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlValue = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* displacedAddress = lifter.builder->CreateAdd(
      controlValue, llvm::ConstantInt::get(controlValue->getType(), 6),
      "generalized_control_slot_plus_6_roll_test");
  auto* dispValue = lifter.GetMemoryValue(displacedAddress, 32);

  lifter.builder->SetInsertPoint(loopBody);
  auto* recurrentControl = lifter.builder->CreateAdd(
      controlValue,
      lifter.builder->CreateSExtOrTrunc(dispValue, llvm::Type::getInt64Ty(context)),
      "rolled_control_state_phi_address");
  lifter.SetMemoryValue(makeI64(context, controlSlot), recurrentControl);
  lifter.SetMemoryValue(makeI64(context, secondControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               secondDisp));
  lifter.SetMemoryValue(makeI64(context, secondControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               secondField));
  lifter.record_generalized_loop_backedge(loopHeader);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  llvm::IRBuilder<> phiBuilder(loopHeader, loopHeader->begin());
  auto* controlPhi = phiBuilder.CreatePHI(llvm::Type::getInt64Ty(context), 2,
                                          "rolled_control_phi");
  controlPhi->addIncoming(makeI64(context, backedgeControl), firstBackedge);
  controlPhi->addIncoming(makeI64(context, secondControl), loopBody);
  auto* displacedControl = lifter.builder->CreateAdd(
      controlPhi, llvm::ConstantInt::get(controlPhi->getType(), 0xC),
      "rolled_generalized_phi_address_plus_12");
  auto* resolved = lifter.GetMemoryValue(displacedControl, 16);
  auto* resolvedPhi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!resolvedPhi || resolvedPhi->getNumIncomingValues() != 2) {
    details =
        "  rolled generalized phi-address load should produce a 2-way phi\n";
    return false;
  }

  bool sawOldBackedge = false;
  bool sawNewBackedge = false;
  for (unsigned i = 0; i < resolvedPhi->getNumIncomingValues(); ++i) {
    auto* incomingBlock = resolvedPhi->getIncomingBlock(i);
    auto actual = readConstantAPInt(resolvedPhi->getIncomingValue(i));
    if (!actual.has_value()) {
      details =
          "  rolled generalized phi-address load incoming value is not concrete\n";
      return false;
    }
    if (incomingBlock == firstBackedge && actual->getZExtValue() == backedgeField) {
      sawOldBackedge = true;
    }
    if (incomingBlock == loopBody && actual->getZExtValue() == secondField) {
      sawNewBackedge = true;
    }
  }
  if (!sawOldBackedge || !sawNewBackedge) {
    details =
        "  rolled generalized phi-address load should preserve both the old backedge and the new recurrent control-derived field\n";
    return false;
  }
  return true;
}



bool runGeneralizedPhiAddressWithDisplacementCreatesPhiOfLoadedValues(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint32_t canonicalValue = 0x12345678ULL;
  constexpr uint32_t backedgeValue = 0x9ABCDEF0ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, canonicalControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               canonicalValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               backedgeValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  lifter.current_address = 0x1400237DCULL;
  llvm::IRBuilder<> phiBuilder(loopHeader, loopHeader->begin());
  auto* controlPhi = phiBuilder.CreatePHI(llvm::Type::getInt64Ty(context), 2,
                                          "generalized_control_phi");
  controlPhi->addIncoming(makeI64(context, canonicalControl), preheader);
  controlPhi->addIncoming(makeI64(context, backedgeControl), firstBackedge);
  auto* displacedAddress = lifter.builder->CreateAdd(
      controlPhi, llvm::ConstantInt::get(controlPhi->getType(), 6),
      "generalized_phi_address_plus_6");
  auto* resolved = lifter.GetMemoryValue(displacedAddress, 32);
  auto* resolvedPhi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!resolvedPhi || resolvedPhi->getNumIncomingValues() != 2) {
    details =
        "  displaced generalized phi-address load should produce a 2-way phi\n";
    return false;
  }

  bool sawCanonical = false;
  bool sawBackedge = false;
  for (unsigned i = 0; i < resolvedPhi->getNumIncomingValues(); ++i) {
    auto* incomingBlock = resolvedPhi->getIncomingBlock(i);
    auto actual = readConstantAPInt(resolvedPhi->getIncomingValue(i));
    if (!actual.has_value()) {
      details =
          "  displaced generalized phi-address load incoming value is not concrete\n";
      return false;
    }
    if (incomingBlock == preheader && actual->getZExtValue() == canonicalValue) {
      sawCanonical = true;
    }
    if (incomingBlock == firstBackedge &&
        actual->getZExtValue() == backedgeValue) {
      sawBackedge = true;
    }
  }

  if (!sawCanonical || !sawBackedge) {
    details =
        "  displaced generalized phi-address load should preserve both incoming concrete values\n";
    return false;
  }
  return true;
}


bool runComputePossibleValuesOnGeneralizedPhiLoad(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalValue = 0x1111222233334444ULL;
  constexpr uint64_t backedgeValue = 0xAAAABBBBCCCCDDDDULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, canonicalControl),
                        makeI64(context, canonicalValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, backedgeControl),
                        makeI64(context, backedgeValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // Obtain a phi-of-concrete-addresses by loading the control slot in
  // generalized loop mode; retrieve_generalized_loop_control_slot_value
  // synthesizes a phi(canonicalControl, backedgeControl) for this load.
  auto* phiAddress = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* pointer = lifter.getPointer(phiAddress);
  auto* load = lifter.builder->CreateLoad(llvm::Type::getInt64Ty(context), pointer,
                                          "generalized_phi_load_probe");
  auto values = lifter.computePossibleValues(load, 0);
  if (values.size() != 2 ||
      !values.contains(llvm::APInt(64, canonicalValue)) ||
      !values.contains(llvm::APInt(64, backedgeValue))) {
    std::ostringstream os;
    os << "  computePossibleValues should enumerate both generalized phi-address loads, got size "
       << values.size() << "\n";
    details = os.str();
    return false;
  }
  return true;
}
bool runComputePossibleValuesOnRolledArithmeticChain(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);
  auto* loopBody =
      llvm::BasicBlock::Create(context, "loop_body", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint16_t backedgeField = 0xB174U;
  constexpr uint16_t secondField = 0x812FU;
  constexpr int32_t backedgeDisp = -1459;
  constexpr int32_t secondDisp = -1337;
  constexpr uint32_t seed32 = 0x5F514EADU;
  constexpr uint32_t add32 = 165327398U;
  constexpr uint64_t tableBase = 5370313337ULL;
  constexpr uint64_t targetA = 0x140020EADULL;
  constexpr uint64_t targetB = 0x140023699ULL;

  auto computeExpectedTableAddress = [&](uint16_t field) -> uint64_t {
    const uint32_t mixed = seed32 ^ static_cast<uint32_t>(field);
    const uint32_t biased = mixed + add32;
    const uint64_t masked = static_cast<uint64_t>(biased) & 0xFFFFULL;
    return tableBase + (masked << 3);
  };
  const uint64_t tableAddrA = computeExpectedTableAddress(backedgeField);
  const uint64_t tableAddrB = computeExpectedTableAddress(secondField);

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               backedgeDisp));
  lifter.SetMemoryValue(makeI64(context, backedgeControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               backedgeField));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlValue = lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* displacedAddress = lifter.builder->CreateAdd(
      controlValue, llvm::ConstantInt::get(controlValue->getType(), 6),
      "generalized_control_slot_plus_6_arith");
  auto* dispValue = lifter.GetMemoryValue(displacedAddress, 32);

  lifter.builder->SetInsertPoint(loopBody);
  auto* recurrentControl = lifter.builder->CreateAdd(
      controlValue,
      lifter.builder->CreateSExtOrTrunc(dispValue, llvm::Type::getInt64Ty(context)),
      "rolled_control_state_arith");
  lifter.SetMemoryValue(makeI64(context, controlSlot), recurrentControl);
  lifter.SetMemoryValue(makeI64(context, secondControl + 0x6),
                        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                               secondDisp));
  lifter.SetMemoryValue(makeI64(context, secondControl + 0xC),
                        llvm::ConstantInt::get(llvm::Type::getInt16Ty(context),
                                               secondField));
  lifter.record_generalized_loop_backedge(loopHeader);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  llvm::IRBuilder<> phiBuilder(loopHeader, loopHeader->begin());
  auto* controlPhi = phiBuilder.CreatePHI(llvm::Type::getInt64Ty(context), 2,
                                          "rolled_control_phi_for_arith");
  controlPhi->addIncoming(makeI64(context, backedgeControl), firstBackedge);
  controlPhi->addIncoming(makeI64(context, secondControl), loopBody);
  auto* displacedControl = lifter.builder->CreateAdd(
      controlPhi, llvm::ConstantInt::get(controlPhi->getType(), 0xC),
      "rolled_generalized_phi_address_plus_12_arith");
  auto* fieldValue = lifter.GetMemoryValue(displacedControl, 16);
  auto* field32 = lifter.builder->CreateTruncOrBitCast(
      lifter.builder->CreateZExt(fieldValue, llvm::Type::getInt64Ty(context)),
      llvm::Type::getInt32Ty(context));
  auto* mixed = lifter.builder->CreateXor(
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), seed32), field32,
      "rolled_arith_mixed");
  auto* biased = lifter.builder->CreateAdd(
      mixed, llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), add32),
      "rolled_arith_biased");
  auto* masked = lifter.builder->CreateAnd(
      lifter.builder->CreateZExt(biased, llvm::Type::getInt64Ty(context)),
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0xFFFFULL),
      "rolled_arith_masked");
  auto* scaled = lifter.builder->CreateShl(
      masked, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 3),
      "rolled_arith_scaled");
  auto* tableAddr = lifter.builder->CreateAdd(
      scaled, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), tableBase),
      "rolled_arith_table_addr");

  auto addrValues = lifter.computePossibleValues(tableAddr, 0);
  if (addrValues.size() != 2 ||
      !addrValues.contains(llvm::APInt(64, tableAddrA)) ||
      !addrValues.contains(llvm::APInt(64, tableAddrB))) {
    std::ostringstream os;
    os << "  rolled arithmetic chain should enumerate both concrete table addresses, got size "
       << addrValues.size();
    for (const auto& value : addrValues) {
      os << " 0x" << std::hex << value.getZExtValue();
    }
    os << " expected 0x" << std::hex << tableAddrA << " and 0x" << tableAddrB << "\n";
    details = os.str();
    return false;
  }

  lifter.SetMemoryValue(makeI64(context, tableAddrA), makeI64(context, targetA));
  lifter.SetMemoryValue(makeI64(context, tableAddrB), makeI64(context, targetB));
  auto* pointer = lifter.getPointer(tableAddr);
  auto* load = lifter.builder->CreateLoad(llvm::Type::getInt64Ty(context), pointer,
                                          "rolled_arith_target_probe");
  auto targetValues = lifter.computePossibleValues(load, 0);
  if (targetValues.size() != 2 ||
      !targetValues.contains(llvm::APInt(64, targetA)) ||
      !targetValues.contains(llvm::APInt(64, targetB))) {
    std::ostringstream os;
    os << "  rolled arithmetic dispatch load should enumerate both concrete targets, got size "
       << targetValues.size() << "\n";
    details = os.str();
    return false;
  }
  return true;
}


  bool runByteTestJoinPreservesBranchValues(std::string& details) {
    LifterUnderTest lifter;
    auto& context = lifter.context;
    auto* preheader =
        llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);
    auto* zeroBlock =
        llvm::BasicBlock::Create(context, "zero_block", lifter.fnc);
    auto* nonZeroBlock =
        llvm::BasicBlock::Create(context, "nonzero_block", lifter.fnc);
    auto* joinBlock =
        llvm::BasicBlock::Create(context, "join_block", lifter.fnc);

    llvm::IRBuilder<>(preheader).CreateBr(loopHeader);
    llvm::IRBuilder<>(firstBackedge).CreateBr(loopHeader);

    lifter.builder->SetInsertPoint(loopHeader);
    llvm::IRBuilder<> phiBuilder(loopHeader, loopHeader->begin());
    auto* bytePhi = phiBuilder.CreatePHI(llvm::Type::getInt8Ty(context), 2,
                                         "byte_test_phi");
    bytePhi->addIncoming(llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), 0),
                         preheader);
    bytePhi->addIncoming(llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), 1),
                         firstBackedge);
    auto* isZero = lifter.builder->CreateICmpEQ(
        bytePhi, llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), 0),
        "byte_zero_cmp");
    lifter.builder->CreateCondBr(isZero, zeroBlock, nonZeroBlock);

    llvm::IRBuilder<> zeroBuilder(zeroBlock);
    auto* zeroValue = llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0x29);
    zeroBuilder.CreateBr(joinBlock);

    llvm::IRBuilder<> nonZeroBuilder(nonZeroBlock);
    auto* nonZeroValue =
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0x6AB);
    nonZeroBuilder.CreateBr(joinBlock);

    llvm::IRBuilder<> joinBuilder(joinBlock);
    auto* joined = joinBuilder.CreatePHI(llvm::Type::getInt64Ty(context), 2,
                                         "byte_test_join_phi");
    joined->addIncoming(zeroValue, zeroBlock);
    joined->addIncoming(nonZeroValue, nonZeroBlock);

    auto values = lifter.computePossibleValues(joined, 0);
    if (values.size() != 2 ||
        !values.contains(llvm::APInt(64, 0x29)) ||
        !values.contains(llvm::APInt(64, 0x6AB))) {
      std::ostringstream os;
      os << "  byte-test join should preserve both branch values, got size "
         << values.size();
      for (const auto& value : values) {
        os << " 0x" << std::hex << value.getZExtValue();
      }
      os << "\n";
      details = os.str();
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopRestoreMergesBackedgeFlagState(std::string& details) {
    LifterUnderTest lifter;
    auto* preheader =
        llvm::BasicBlock::Create(lifter.context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(lifter.context, "first_backedge", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);
    lifter.builder->SetInsertPoint(preheader);
    auto* canonicalPf = lifter.builder->getInt1(false);
    lifter.SetFlagValue_impl(FLAG_PF, canonicalPf);
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(firstBackedge);
    auto* backedgePf = lifter.builder->getInt1(true);
    lifter.SetFlagValue_impl(FLAG_PF, backedgePf);
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    auto* mergedPf = lifter.getFlag(FLAG_PF);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(mergedPf);
    if (!phi) {
      details =
          "  generalized loop restore should merge canonical and backedge PF through a phi\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto* incomingValue = phi->getIncomingValue(i);
      if (incomingBlock == preheader && incomingValue == canonicalPf) {
        sawCanonical = true;
      }
      if (incomingBlock == firstBackedge && incomingValue == backedgePf) {
        sawBackedge = true;
      }
    }

    if (!sawCanonical || !sawBackedge) {
      details =
          "  generalized loop flag phi did not preserve both canonical and backedge PF values\n";
      return false;
    }
    return true;
  }


  bool runGeneralizedLoopRestoreMergesBackedgeRegisterState(
      std::string& details) {
    LifterUnderTest lifter;
    auto* preheader =
        llvm::BasicBlock::Create(lifter.context, "preheader", lifter.fnc);
    auto* firstBackedge =
        llvm::BasicBlock::Create(lifter.context, "first_backedge", lifter.fnc);
    auto* loopBody =
        llvm::BasicBlock::Create(lifter.context, "loop_body", lifter.fnc);
    auto* loopHeader =
        llvm::BasicBlock::Create(lifter.context, "loop_header", lifter.fnc);

    lifter.builder->SetInsertPoint(preheader);
    auto* canonicalRbx = makeI64(lifter.context, 37);
    lifter.SetRegisterValue(RegisterUnderTest::RBX, canonicalRbx);
    lifter.branch_backup(loopHeader);

    lifter.builder->SetInsertPoint(firstBackedge);
    auto* firstBackedgeRbx = lifter.builder->CreateSub(
        makeI64(lifter.context, 37), makeI64(lifter.context, 1), "rbx_dec_init");
    lifter.SetRegisterValue(RegisterUnderTest::RBX, firstBackedgeRbx);
    lifter.branch_backup(loopHeader, /*generalized=*/true);

    lifter.load_generalized_backup(loopHeader);
    auto* mergedRbx = lifter.GetRegisterValue(RegisterUnderTest::RBX);
    auto* phi = llvm::dyn_cast<llvm::PHINode>(mergedRbx);
    if (!phi) {
      details =
          "  generalized loop restore should merge canonical and widened backedge RBX through a phi\n";
      return false;
    }

    bool sawCanonical = false;
    bool sawWidenedBackedge = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* incomingBlock = phi->getIncomingBlock(i);
      auto* incomingValue = phi->getIncomingValue(i);
      if (incomingBlock == preheader && incomingValue == canonicalRbx) {
        sawCanonical = true;
      }
      if (incomingBlock == firstBackedge &&
          llvm::isa<llvm::UndefValue>(incomingValue)) {
        sawWidenedBackedge = true;
      }
    }

    if (!sawCanonical || !sawWidenedBackedge) {
      details =
          "  generalized loop RBX phi should keep the canonical incoming value and widen the first concrete backedge\n";
      return false;
    }

    lifter.builder->SetInsertPoint(loopBody);
    auto* recurrentRbx = lifter.builder->CreateSub(
        phi, llvm::ConstantInt::get(phi->getType(), 1), "rbx_dec_loop");
    lifter.SetRegisterValue(RegisterUnderTest::RBX, recurrentRbx);
    lifter.record_generalized_loop_backedge(loopHeader);

    bool sawRecurrentIncoming = false;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      if (phi->getIncomingBlock(i) == loopBody &&
          phi->getIncomingValue(i) == recurrentRbx) {
        sawRecurrentIncoming = true;
      }
    }
    if (!sawRecurrentIncoming) {
      details =
          "  generalized loop backedge should add the live recurrent RBX value to the header phi\n";
      return false;
    }

    lifter.load_backup(loopHeader);
    if (lifter.GetRegisterValue(RegisterUnderTest::RBX) != canonicalRbx) {
      details =
          "  canonical loop-header backup should remain available after generalized restore\n";
      return false;
    }
    return true;
  }



  int runCustomKnownBitsTests(const std::string& suiteFilter) {
    int failures = 0;

    const std::string scalarCase = "custom_knownbits_scalar_i64_constant";
    if (shouldRunByFilter(scalarCase, suiteFilter)) {
      std::string details;
      const bool ok = runKnownBitsI64ConstantCase(details);
      std::cout << "[" << (ok ? "  OK  " : " FAIL ") << "] " << scalarCase
                << "\n";
      if (!ok && !details.empty()) {
        std::cout << details;
      }
      failures += !ok;
    }

    const std::string simdCase = "custom_knownbits_simd_i128_fallback";
    if (shouldRunByFilter(simdCase, suiteFilter)) {
      std::string details;
      const bool ok = runKnownBitsSimdFallbackCase(details);
      std::cout << "[" << (ok ? "  OK  " : " FAIL ") << "] " << simdCase
                << "\n";
      if (!ok && !details.empty()) {
        std::cout << details;
      }
      failures += !ok;
    }

    // Call-ABI contract tests
    auto runCustom = [&](const std::string& name, auto method) {
      if (!shouldRunByFilter(name, suiteFilter)) return;
      std::string details;
      const bool ok = (this->*method)(details);
      std::cout << "[" << (ok ? "  OK  " : " FAIL ") << "] " << name << "\n";
      if (!ok && !details.empty()) std::cout << details;
      failures += !ok;
    };
    runCustom("generalized_loop_control_slot_creates_phi",
             &InstructionTester::runGeneralizedLoopControlSlotCreatesPhi);
    runCustom("generalized_loop_control_slot_displacement_creates_phi_of_loaded_values",
             &InstructionTester::runGeneralizedLoopControlSlotDisplacementCreatesPhiOfLoadedValues);
    runCustom("solve_path_skips_raw_zero_in_multi_target_switch",
             &InstructionTester::runSolvePathSkipsRawZeroInMultiTargetSwitch);
    runCustom("generalized_loop_target_slot_creates_phi",
             &InstructionTester::runGeneralizedLoopTargetSlotCreatesPhi);
    runCustom("call_abi_compat_preserves_volatile",
             &InstructionTester::runCallAbiCompatPreservesVolatile);
    runCustom("call_abi_strict_clobbers_volatile",
             &InstructionTester::runCallAbiStrictClobbersVolatile);
    runCustom("call_abi_default_is_strict",
             &InstructionTester::runCallAbiDefaultIsStrict);
    runCustom("function_signature_zero_arg_preserved",
             &InstructionTester::runFunctionSignatureZeroArgPreserved);
    runCustom("function_signature_binary_name_lookup",
             &InstructionTester::runFunctionSignatureBinaryNameLookup);
    runCustom("function_signature_binary_fallback_args",
             &InstructionTester::runFunctionSignatureBinaryFallbackArgs);
    runCustom("scas_basic_pointer_advance",
             &InstructionTester::runScasBasicPointerAdvance);
    runCustom("scas_repeat_prefixes_rejected",
             &InstructionTester::runScasRepeatPrefixesRejected);
    runCustom("loop_addrsize_override_rejected",
             &InstructionTester::runLoopAddressSizeOverrideRejected);
    runCustom("solve_load_normalizes_mapped_rva_candidate",
             &InstructionTester::runSolveLoadNormalizesMappedRvaCandidate);
    runCustom("loop_generalization_conditional_branch_allowed",
             &InstructionTester::runLoopGeneralizationConditionalBranchAllowed);
    runCustom("loop_generalization_direct_jump_allowed",
             &InstructionTester::runLoopGeneralizationDirectJumpAllowed);
    runCustom("loop_generalization_indirect_jump_blocked_when_unresolved",
             &InstructionTester::runLoopGeneralizationIndirectJumpBlockedWhenUnresolved);
    runCustom("int29_fastfail_lowered_to_noreturn_call",
             &InstructionTester::runInt29FastfailLoweredToNoReturnCall);
    runCustom("xgetbv_returns_deterministic_xcr0",
             &InstructionTester::runXgetbvReturnsDeterministicXcr0);
    runCustom("loop_generalization_indirect_jump_allowed_when_resolved",
             &InstructionTester::runLoopGeneralizationIndirectJumpAllowedWhenResolved);
    runCustom("loop_generalization_ret_blocked",
             &InstructionTester::runLoopGeneralizationRetBlocked);
    runCustom("pending_generalized_loop_indirect_jump_allowed_when_resolved",
             &InstructionTester::runPendingGeneralizedLoopIndirectJumpAllowedWhenResolved);
    runCustom("pending_generalized_loop_ret_blocked",
             &InstructionTester::runPendingGeneralizedLoopRetBlocked);
    runCustom("tiny_outlined_call_bypasses_outline_policy",
             &InstructionTester::runTinyOutlinedCallBypassesOutlinePolicy);
    runCustom("structured_loop_header_allows_conditional_backedge",
             &InstructionTester::runStructuredLoopHeaderAllowsConditionalBackedge);
    runCustom("solve_load_phi_address_creates_phi_of_loaded_values",
             &InstructionTester::runSolveLoadPhiAddressCreatesPhiOfLoadedValues);
    runCustom("solve_load_phi_address_with_displacement_creates_phi_of_loaded_values",
             &InstructionTester::runSolveLoadPhiAddressWithDisplacementCreatesPhiOfLoadedValues);
    runCustom("generalized_loop_local_phi_address_creates_phi_of_loaded_values",
             &InstructionTester::runGeneralizedLoopLocalPhiAddressCreatesPhiOfLoadedValues);
    runCustom("structured_loop_header_allows_jump_chain",
             &InstructionTester::runStructuredLoopHeaderAllowsJumpChain);

    runCustom("structured_loop_header_rejects_acyclic_backward_branch",
             &InstructionTester::runStructuredLoopHeaderRejectsAcyclicBackwardBranch);
    runCustom("structured_loop_header_rejects_non_conditional_terminator",
             &InstructionTester::runStructuredLoopHeaderRejectsNonConditionalTerminator);
    runCustom("structured_loop_header_rejects_multiple_predecessors",
             &InstructionTester::runStructuredLoopHeaderRejectsMultiplePredecessors);
    runCustom("generalized_loop_without_bypass_tag_keeps_normal_restore",
             &InstructionTester::runGeneralizedLoopWithoutBypassTagKeepsNormalRestore);
    runCustom("generalized_loop_with_bypass_tag_uses_generalized_restore",
             &InstructionTester::runGeneralizedLoopWithBypassTagUsesGeneralizedRestore);
    runCustom("generalized_loop_bypass_tag_clears_after_promotion",
             &InstructionTester::runGeneralizedLoopBypassTagClearsAfterPromotion);
    runCustom("promoted_generalized_loop_restores_canonical_backup",
             &InstructionTester::runPromotedGeneralizedLoopRestoresCanonicalBackup);
    runCustom("generalized_loop_third_backedge_preserves_all_three_snapshots",
             &InstructionTester::runGeneralizedLoopThirdBackedgePreservesAllThreeSnapshots);
    runCustom("generalized_loop_load_backup_with_three_backedges_produces_four_way_phi",
             &InstructionTester::runGeneralizedLoopLoadBackupWithThreeBackedgesProducesFourWayPhi);
    runCustom("generalized_loop_non_themida_control_slot_produces_no_phi",
             &InstructionTester::runGeneralizedLoopNonThemidaControlSlotProducesNoPhi);
    runCustom("generalized_loop_nested_inner_overwrites_outer_active_state",
             &InstructionTester::runGeneralizedLoopNestedInnerOverwritesOuterActiveState);
    runCustom("generalized_loop_restore_merges_backedge_flag_state",
             &InstructionTester::runGeneralizedLoopRestoreMergesBackedgeFlagState);
    runCustom("generalized_loop_restore_merges_backedge_register_state",
             &InstructionTester::runGeneralizedLoopRestoreMergesBackedgeRegisterState);
    runCustom("set_register_value_zero_extends_32bit_writes",
             &InstructionTester::runSetRegisterValueZeroExtends32BitWrites);
    runCustom("compute_possible_values_on_rolled_arithmetic_chain",
             &InstructionTester::runComputePossibleValuesOnRolledArithmeticChain);
    runCustom("byte_test_join_preserves_branch_values",
             &InstructionTester::runByteTestJoinPreservesBranchValues);
    runCustom("compute_possible_values_on_generalized_phi_load",
             &InstructionTester::runComputePossibleValuesOnGeneralizedPhiLoad);
    runCustom("rolled_generalized_phi_address_uses_advanced_pair",
             &InstructionTester::runRolledGeneralizedPhiAddressUsesAdvancedPair);
    runCustom("solve_path_resolves_generalized_phi_load_target",
             &InstructionTester::runSolvePathResolvesGeneralizedPhiLoadTarget);
    runCustom("generalized_phi_address_with_displacement_creates_phi_of_loaded_values",
             &InstructionTester::runGeneralizedPhiAddressWithDisplacementCreatesPhiOfLoadedValues);
    runCustom("solve_load_infers_concrete_base_from_tracked_load",
             &InstructionTester::runSolveLoadInfersConcreteBaseFromTrackedLoad);
    runCustom("compute_possible_values_preserves_cast_widths",
             &InstructionTester::runComputePossibleValuesPreservesCastWidths);
    runCustom("compute_possible_values_enumerates_phi_incomings",
             &InstructionTester::runComputePossibleValuesEnumeratesPhiIncomings);
    runCustom("compute_possible_values_circular_phi_bails_via_depth_guard",
             &InstructionTester::runComputePossibleValuesCircularPhiBailsViaDepthGuard);
    runCustom("compute_possible_values_trunc_to_i1_preserves_width",
             &InstructionTester::runComputePossibleValuesTruncToI1PreservesWidth);
    runCustom("generalized_loop_control_field_load_creates_phi",
             &InstructionTester::runGeneralizedLoopControlFieldLoadCreatesPhi);
    runCustom("solve_path_prefers_mapped_target_over_null_for_indirect_jump",
             &InstructionTester::runSolvePathPrefersMappedTargetOverNullForIndirectJump);
    runCustom("solve_path_widens_mapped_rva_target",
             &InstructionTester::runSolvePathWidensMappedRvaTarget);
    runCustom("normalize_runtime_target_widens_mapped_rva_target",
             &InstructionTester::runNormalizeRuntimeTargetWidensMappedRvaTarget);

    return failures;
  }

  bool runTestCase(const InstructionTestCase& testCase, bool checkFlags) {
    if (testCase.instructionBytes.empty()) {
      std::cout << "Empty instruction byte sequence" << std::endl;
      return false;
    }

    LifterUnderTest lifter;
    lifter.hadConditionalBranch = false;
    lifter.lastBranchTaken = false;

    for (const auto& reg : testCase.initialRegisters) {
      const auto registerSize = getRegisterSize(reg.reg);
      auto normalized = reg.value.zextOrTrunc(registerSize);
      lifter.SetRegisterValue(
          reg.reg, llvm::ConstantInt::get(lifter.builder->getContext(), normalized));
    }

    for (const auto& flag : testCase.initialFlags) {
      lifter.SetFlagValue_impl(flag.flag, lifter.builder->getInt1(flag.value));
    }

    lifter.liftBytes(testCase.instructionBytes.data(),
                    testCase.instructionBytes.size());

    std::ostringstream errors;

    for (const auto& expected : testCase.expectedRegisters) {
      auto actual = readConstantAPInt(lifter.GetRegisterValue(expected.reg));
      if (!actual.has_value()) {
        errors << "  register is not constant: "
               << magic_enum::enum_name(expected.reg) << "\n";
        continue;
      }

      const auto expectedWidth = static_cast<unsigned>(getRegisterSize(expected.reg));
      if (actual->getBitWidth() != expectedWidth) {
        errors << "  register width mismatch " << magic_enum::enum_name(expected.reg)
               << ": expected_bits=" << expectedWidth
               << " actual_bits=" << actual->getBitWidth() << "\n";
        continue;
      }

      auto expectedValue = expected.value.zextOrTrunc(expectedWidth);
      if (actual.value() != expectedValue) {
        errors << "  register mismatch " << magic_enum::enum_name(expected.reg)
               << ": expected=" << formatAPIntHex(expectedValue)
               << " actual=" << formatAPIntHex(actual.value()) << "\n";
      }
    }

    if (checkFlags) {
      for (const auto& expected : testCase.expectedFlags) {
        auto actual = readConstantBool(lifter.GetFlagValue_impl(expected.flag));
        if (!actual.has_value()) {
          errors << "  flag is not constant: "
                 << magic_enum::enum_name(expected.flag) << "\n";
          continue;
        }

        if (actual.value() != expected.value) {
          errors << "  flag mismatch " << magic_enum::enum_name(expected.flag)
                 << ": expected=" << expected.value
                 << " actual=" << actual.value() << "\n";
        }
      }
    }

    // Branch-taken check for jcc handlers
    if (testCase.expectedBranchTaken.has_value()) {
      if (!lifter.hadConditionalBranch) {
        errors << "  expected a conditional branch but none was taken\n";
      } else if (!lifter.lastConditionalBranchResolved) {
        errors << "  expected resolved conditional branch direction but it remained symbolic\n";
      } else if (lifter.lastBranchTaken != testCase.expectedBranchTaken.value()) {
        errors << "  branch_taken mismatch: expected="
               << testCase.expectedBranchTaken.value()
               << " actual=" << lifter.lastBranchTaken << "\n";
      }
    }

    const auto details = errors.str();
    if (!details.empty()) {
      std::cout << details;
      return false;
    }

    return true;
  }
};
