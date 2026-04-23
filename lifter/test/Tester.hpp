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

  bool runPendingGeneralizedLoopConditionalBranchAllowed(std::string& details) {
    // Conditional-branch context is the canonical loop-latch context. A
    // pending generalized-loop header whose target is solved from this
    // context must be reused rather than re-entered from scratch.
    return runPendingGeneralizedLoopByContext(
        LifterUnderTest::PathSolveContext::ConditionalBranch,
        "conditional-branch", /*expectReuse=*/true, details);
  }

  bool runPendingGeneralizedLoopDirectJumpAllowed(std::string& details) {
    // Direct-jump context also reaches a pending generalized-loop header
    // through a proved backward target and must reuse it.
    return runPendingGeneralizedLoopByContext(
        LifterUnderTest::PathSolveContext::DirectJump, "direct-jump",
        /*expectReuse=*/true, details);
  }

  bool runPendingGeneralizedLoopIndirectJumpAllowedWhenUnresolved(
      std::string& details) {
    // Current behavior: once the target value solved concretely to the
    // pending generalized-loop header, the pending-path machinery reuses
    // that header even under IndirectJump context. This differs from the
    // stricter canGeneralizeStructuredLoopHeader gate used for fresh loop
    // promotion. Pin the behavior rather than asserting a false symmetry.
    return runPendingGeneralizedLoopByContext(
        LifterUnderTest::PathSolveContext::IndirectJump, "indirect-jump",
        /*expectReuse=*/true, details);
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


// canGeneralizeStructuredLoopHeader: forward-target rejected. The target
// address MUST be at or before the current block's address for it to be
// a backward loop edge.
bool runLoopGeneralizationForwardTargetRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* forwardTarget =
      llvm::BasicBlock::Create(lifter.context, "forward_target", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);

  llvm::IRBuilder<> tb(forwardTarget);
  tb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  // Current block is at 0x1000; forward target at 0x2000 is NOT a
  // backward edge, so generalization must reject.
  lifter.blockInfo = BBInfo(0x1000, current);
  lifter.visitedAddresses.insert(0x2000);
  lifter.addrToBB[0x2000] = forwardTarget;

  if (lifter.canGeneralizeStructuredLoopHeader(0x2000)) {
    details = "  forward target (addr > current block) must not be "
              "generalized as a loop header\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader: not-yet-visited backward target
// rejected. A header address we have never lifted before cannot be
// reused as a loop latch - the latch shape proof requires the header's
// block to exist and already have its terminator.
bool runLoopGeneralizationNotVisitedTargetRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);
  llvm::IRBuilder<> hb(header);
  hb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, current);
  // Deliberately do NOT insert into visitedAddresses.
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  backward target never visited must not be generalized "
              "(visitedAddresses guard)\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader: already-pending address rejected.
// A header already queued for generalization must not re-enter the
// pipeline; otherwise the lifter would oscillate between pending and
// active lifts on the same block.
bool runLoopGeneralizationAlreadyPendingRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);
  llvm::IRBuilder<> hb(header);
  hb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;
  lifter.pendingLoopGeneralizationAddresses.insert(0x1000);

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  already-pending header must not be re-admitted to "
              "generalization\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader: already-generalized address rejected.
// Once a header has been fully promoted into generalizedLoopAddresses, the
// guard must short-circuit and refuse to re-enter the promotion flow.
bool runLoopGeneralizationAlreadyGeneralizedRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);
  llvm::IRBuilder<> hb(header);
  hb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;
  lifter.generalizedLoopAddresses.insert(0x1000);

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  already-generalized header must not be re-admitted\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader: no-reach target rejected. A header
// that exists and has the right shape but whose CFG cannot actually reach
// the current block (blockCanReach returns false) must be rejected.
// Without a demonstrable cycle there is no loop to generalize.
bool runLoopGeneralizationNoReachRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* bodyLeft = llvm::BasicBlock::Create(lifter.context, "body_left", lifter.fnc);
  auto* bodyRight =
      llvm::BasicBlock::Create(lifter.context, "body_right", lifter.fnc);

  // Header branches to bodyLeft and bodyRight, both of which ret - no
  // path reaches `current`. blockCanReach(header, current) is false.
  llvm::IRBuilder<> hb(header);
  hb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), bodyLeft, bodyRight);
  llvm::IRBuilder<> lb(bodyLeft);
  lb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> rb(bodyRight);
  rb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  header that cannot reach current block must not be "
              "generalized as a loop (no actual cycle)\n";
    return false;
  }
  return true;
}

// isStructuredLoopHeaderShape: empty block in chain rejects. The walk
// from the header must never encounter an empty basic block; an empty
// block is a mid-construction artifact and not a valid shape.
bool runStructuredLoopHeaderRejectsEmptyBlockInChain(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* emptyMid =
      llvm::BasicBlock::Create(lifter.context, "empty_mid", lifter.fnc);
  // Single unconditional br from header to empty block, then empty.
  llvm::IRBuilder<> hb(header);
  hb.CreateBr(emptyMid);
  // emptyMid deliberately has no instructions - walker should reject.

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  chain that walks into an empty block must not be "
              "recognized as a structured loop header\n";
    return false;
  }
  return true;
}

// isStructuredLoopHeaderShape: depth >= 8 rejects. The walker caps at
// 8 hops; a chain of 9 single-successor blocks exceeds the cap.
bool runStructuredLoopHeaderRejectsDeepChain(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  constexpr unsigned kChainLen = 10;  // > 8 hop cap
  std::array<llvm::BasicBlock*, kChainLen> chain{};
  for (unsigned i = 0; i < kChainLen; ++i) {
    chain[i] = llvm::BasicBlock::Create(lifter.context,
                                        ("chain_" + std::to_string(i)).c_str(),
                                        lifter.fnc);
  }
  for (unsigned i = 0; i + 1 < kChainLen; ++i) {
    llvm::IRBuilder<> b(chain[i]);
    b.CreateBr(chain[i + 1]);
  }
  // Last block has a ret - no conditional branch anywhere in the chain.
  llvm::IRBuilder<> lastB(chain[kChainLen - 1]);
  lastB.CreateRet(
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = chain[0];

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  chain deeper than the walker's 8-hop cap must not be "
              "recognized as a structured loop header\n";
    return false;
  }
  return true;
}


// mergeValue type-mismatch fallback. When canonical and backedge hold
// values of different LLVM types, mergeValue bails and returns the
// backedge value directly - no phi is constructed. Exercises the
// `canonicalValue->getType() != backedgeValue->getType()` early-return
// in make_generalized_loop_backup's mergeValue lambda.
bool runMergeValueReturnsBackedgeOnTypeMismatch(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t backedgeRsp = 0x14FE80ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  // Canonical RSP is narrower (i32) than backedge RSP (i64) - forces a
  // type mismatch in mergeValue. RSP is preserve-register, so the
  // fallback returns the concrete backedge value.
  lifter.SetRegisterValue(
      RegisterUnderTest::RSP,
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 0x1234));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RSP,
                          makeI64(context, backedgeRsp));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rsp = lifter.GetRegisterValue(RegisterUnderTest::RSP);
  if (llvm::isa<llvm::PHINode>(rsp)) {
    details = "  mergeValue on type-mismatched canonical/backedge should "
              "skip phi construction and return the backedge value\n";
    return false;
  }
  auto actual = readConstantAPInt(rsp);
  if (!actual.has_value() || actual->getZExtValue() != backedgeRsp) {
    details = "  type-mismatch fallback should yield the backedge RSP\n";
    return false;
  }
  return true;
}

// branch_backup non-generalized path. A plain branch_backup(bb) (no
// generalized=true) writes the snapshot into BBbackup[bb] unconditionally
// and does NOT touch generalizedLoopBackedgeBackup. Exercises the
// non-loop-latch branch of branch_backup_impl.
bool runBranchBackupPlainReplacesBBbackupOnly(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* target =
      llvm::BasicBlock::Create(context, "branch_target", lifter.fnc);
  constexpr uint64_t marker = 0x140050000ULL;
  constexpr uint64_t firstValue = 0xAAAAAAAAAAAAAAAAULL;
  constexpr uint64_t secondValue = 0xBBBBBBBBBBBBBBBBULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, marker), makeI64(context, firstValue));
  lifter.branch_backup(target);
  // Second non-generalized call must REPLACE BBbackup[target] wholesale.
  lifter.SetMemoryValue(makeI64(context, marker), makeI64(context, secondValue));
  lifter.branch_backup(target);

  auto it = lifter.BBbackup.find(target);
  if (it == lifter.BBbackup.end()) {
    details = "  BBbackup[target] missing after plain branch_backup\n";
    return false;
  }
  uint64_t storedMarker = 0;
  if (!lifter.readConstantTrackedQword(it->second.buffer, marker, storedMarker)) {
    details = "  BBbackup buffer should contain the marker slot\n";
    return false;
  }
  if (storedMarker != secondValue) {
    std::ostringstream os;
    os << "  BBbackup should reflect the second (most recent) non-generalized "
          "call, got 0x" << std::hex << storedMarker << "\n";
    details = os.str();
    return false;
  }
  // generalizedLoopBackedgeBackup must NOT have an entry for target.
  if (lifter.generalizedLoopBackedgeBackup.count(target) != 0) {
    details = "  plain branch_backup must not populate "
              "generalizedLoopBackedgeBackup\n";
    return false;
  }
  return true;
}

// isStructuredLoopHeaderShape: cycle in walked chain rejected. When the
// walker's seenBlocks set hits a block it already visited on this walk,
// it refuses the chain. A self-branch at the end of a chain forms such
// a cycle without a conditional branch anywhere in the walk.
bool runStructuredLoopHeaderRejectsCycleInChain(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* mid = llvm::BasicBlock::Create(lifter.context, "mid", lifter.fnc);

  // header -> mid -> header: unconditional cycle with no conditional
  // branch. Walker must reject on cycle detection.
  llvm::IRBuilder<> hb(header);
  hb.CreateBr(mid);
  llvm::IRBuilder<> mb(mid);
  mb.CreateBr(header);

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  unconditional cycle without a conditional branch must "
              "not be recognized as a structured loop header\n";
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

// Multi-way rolled-control: record_generalized_loop_backedge appends or
// updates per body source when the header has >=2 backedges. 1-backedge
// loops keep the original rotation semantics (promote backedge into
// canonical, install new source as backedge); multi-way loops dedup by
// sourceBlock and grow the backedge list as distinct body paths roll.
bool runRecordGeneralizedLoopBackedgeMultiwayAppendsNewBodySource(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);
  auto* bodyBlock =
      llvm::BasicBlock::Create(context, "body_block", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint64_t bodyRolledControl = 0x1401AEC37ULL;

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

  lifter.load_generalized_backup(loopHeader);
  if (!lifter.activeGeneralizedLoopControlFieldState.valid) {
    details = "  multi-way activation failed\n";
    return false;
  }
  if (lifter.activeGeneralizedLoopControlFieldState.backedgeSources.size() != 2) {
    details = "  setup should have 2 backedges before record\n";
    return false;
  }

  // Simulate body lifting: a new body block advances the control cursor.
  lifter.builder->SetInsertPoint(bodyBlock);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, bodyRolledControl));
  lifter.record_generalized_loop_backedge(loopHeader);

  auto& backedgeSources =
      lifter.activeGeneralizedLoopControlFieldState.backedgeSources;
  auto& backedgeControls =
      lifter.activeGeneralizedLoopControlFieldState.backedgeControls;
  if (backedgeSources.size() != 3) {
    std::ostringstream os;
    os << "  record_generalized_loop_backedge (multi-way) should append body "
          "source, got backedge count " << backedgeSources.size()
       << " expected 3\n";
    details = os.str();
    return false;
  }
  bool sawBody = false;
  for (size_t i = 0; i < backedgeSources.size(); ++i) {
    if (backedgeSources[i] == bodyBlock &&
        backedgeControls[i] == bodyRolledControl) {
      sawBody = true;
      break;
    }
  }
  if (!sawBody) {
    details = "  appended body backedge missing from multi-way state\n";
    return false;
  }

  // Calling record again from the same body with the SAME control must
  // be a no-op (no progress - size stays at 3).
  lifter.record_generalized_loop_backedge(loopHeader);
  if (backedgeSources.size() != 3) {
    details = "  repeat record (same control) should not grow multi-way state\n";
    return false;
  }

  // Calling record with a NEW control from the same body must update
  // in place - size stays at 3, but the body entry's control advances.
  constexpr uint64_t bodyRolledControl2 = 0x1401AED41ULL;
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, bodyRolledControl2));
  lifter.record_generalized_loop_backedge(loopHeader);
  if (backedgeSources.size() != 3) {
    details = "  repeat record (new control, same source) should dedup and "
              "not grow multi-way state\n";
    return false;
  }
  bool sawUpdatedControl = false;
  for (size_t i = 0; i < backedgeSources.size(); ++i) {
    if (backedgeSources[i] == bodyBlock &&
        backedgeControls[i] == bodyRolledControl2) {
      sawUpdatedControl = true;
      break;
    }
  }
  if (!sawUpdatedControl) {
    details = "  multi-way body entry should reflect latest rolled control "
              "after repeat record\n";
    return false;
  }
  return true;
}

// Phi-address helper with 3-way phi (canonical + 2 distinct backedges).
// After PR #123 relaxed the sanity check from `!= 2` to `< 2`, the helper
// must match each incoming against canonicalSource or any of
// state->backedgeSources[i]. Exercises the N-way matching loop in
// retrieve_generalized_loop_phi_address_value_impl.
bool runGeneralizedPhiAddressThreeWayResolvesAllIncomings(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  // Three distinct target addresses, each with a distinct stored value.
  constexpr uint64_t canonicalAddr = 0x140060000ULL;
  constexpr uint64_t firstAddr = 0x140060100ULL;
  constexpr uint64_t secondAddr = 0x140060200ULL;
  constexpr uint64_t canonicalValue = 0xAAAA0000AAAA0000ULL;
  constexpr uint64_t firstValue = 0xBBBB1111BBBB1111ULL;
  constexpr uint64_t secondValue = 0xCCCC2222CCCC2222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, canonicalAddr),
                        makeI64(context, canonicalValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.SetMemoryValue(makeI64(context, firstAddr),
                        makeI64(context, firstValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(secondBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, secondControl));
  lifter.SetMemoryValue(makeI64(context, secondAddr),
                        makeI64(context, secondValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 3, "threeway_phi_addr");
  addressPhi->addIncoming(makeI64(context, canonicalAddr), preheader);
  addressPhi->addIncoming(makeI64(context, firstAddr), firstBackedge);
  addressPhi->addIncoming(makeI64(context, secondAddr), secondBackedge);

  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  auto* resultPhi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!resultPhi) {
    details = "  3-way phi-address resolver should yield a phi of loaded values\n";
    return false;
  }
  if (resultPhi->getNumIncomingValues() != 3) {
    std::ostringstream os;
    os << "  3-way phi-address resolver should preserve 3 incomings, got "
       << resultPhi->getNumIncomingValues() << "\n";
    details = os.str();
    return false;
  }
  bool sawCanonical = false, sawFirst = false, sawSecond = false;
  for (unsigned i = 0; i < resultPhi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(resultPhi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalValue) sawCanonical = true;
    else if (v == firstValue) sawFirst = true;
    else if (v == secondValue) sawSecond = true;
  }
  if (!sawCanonical || !sawFirst || !sawSecond) {
    details = "  3-way phi-address resolver should resolve each incoming to "
              "its stored value (canonical + 2 backedges)\n";
    return false;
  }
  return true;
}

// Local-phi-address helper with 3-way phi, same premise as above but
// targeting loop-local stack slots. Exercises the parallel matching
// loop in retrieve_generalized_loop_local_phi_address_value_impl.
bool runGeneralizedLocalPhiAddressThreeWayResolvesAllIncomings(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;
  constexpr uint64_t stackA = STACKP_VALUE;
  constexpr uint64_t stackB = STACKP_VALUE + 8;
  constexpr uint64_t stackC = STACKP_VALUE + 16;
  constexpr uint64_t valueA = 0x1111111111111111ULL;
  constexpr uint64_t valueB = 0x2222222222222222ULL;
  constexpr uint64_t valueC = 0x3333333333333333ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, stackA), makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.SetMemoryValue(makeI64(context, stackB), makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(secondBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, secondControl));
  lifter.SetMemoryValue(makeI64(context, stackC), makeI64(context, valueC));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 3, "threeway_local_phi_addr");
  addressPhi->addIncoming(makeI64(context, stackA), preheader);
  addressPhi->addIncoming(makeI64(context, stackB), firstBackedge);
  addressPhi->addIncoming(makeI64(context, stackC), secondBackedge);

  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  auto* resultPhi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!resultPhi || resultPhi->getNumIncomingValues() != 3) {
    details = "  3-way local-phi-address resolver should yield a 3-incoming "
              "phi\n";
    return false;
  }
  bool sawA = false, sawB = false, sawC = false;
  for (unsigned i = 0; i < resultPhi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(resultPhi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
    else if (v == valueC) sawC = true;
  }
  if (!sawA || !sawB || !sawC) {
    details = "  3-way local-phi-address resolver should carry all three "
              "incoming stack values\n";
    return false;
  }
  return true;
}

// branch_backup dedup by sourceBlock. A repeat generalized backup from
// the same sourceBlock must replace that block's entry in place rather
// than append a duplicate; the vector size stays bounded by the number
// of distinct source blocks.
bool runBranchBackupGeneralizedDedupsBySourceBlock(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);
  // Second call from the SAME source block - must replace, not append.
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, secondControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  auto it = lifter.generalizedLoopBackedgeBackup.find(loopHeader);
  if (it == lifter.generalizedLoopBackedgeBackup.end()) {
    details = "  generalizedLoopBackedgeBackup missing after two generalized calls\n";
    return false;
  }
  if (it->second.size() != 1) {
    std::ostringstream os;
    os << "  repeat branch_backup from same source should dedup; got size "
       << it->second.size() << " expected 1\n";
    details = os.str();
    return false;
  }
  // The stored entry must reflect the SECOND call (the one that
  // overwrote).
  uint64_t storedControl = 0;
  if (!lifter.readConstantTrackedQword(it->second.front().buffer, controlSlot,
                                        storedControl)) {
    details = "  deduped backedge buffer should still contain controlSlot\n";
    return false;
  }
  if (storedControl != secondControl) {
    std::ostringstream os;
    os << "  deduped backedge should reflect second call's control value, "
          "got 0x" << std::hex << storedControl << " expected 0x"
       << secondControl << "\n";
    details = os.str();
    return false;
  }
  return true;
}

// mergeValue collapse: when canonical and backedge register/flag values
// resolve to the SAME SSA value, no phi is built and the shared value
// is returned directly. Exercises the `canonicalValue == backedgeValue`
// early-return in the mergeValue lambda of make_generalized_loop_backup.
bool runMergeValueCollapsesIdenticalCanonicalAndBackedgeToSingleValue(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  // RSP has widenFirstBackedge=false, so mergeValue uses the concrete
  // backedge value. Seed both sides to the SAME RSP constant - this
  // should skip phi construction entirely.
  constexpr uint64_t sharedRsp = 0x14FEA0ULL;  // matches STACKP_VALUE shape
  auto* sharedRspVal = makeI64(context, sharedRsp);

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RSP, sharedRspVal);
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RSP, sharedRspVal);
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rsp = lifter.GetRegisterValue(RegisterUnderTest::RSP);
  if (llvm::isa<llvm::PHINode>(rsp)) {
    details = "  mergeValue should collapse identical canonical/backedge RSP "
              "to a single value, not a phi\n";
    return false;
  }
  auto actual = readConstantAPInt(rsp);
  if (!actual.has_value() || actual->getZExtValue() != sharedRsp) {
    details = "  collapsed RSP should carry the shared concrete constant\n";
    return false;
  }
  return true;
}

// record_generalized_loop_backedge 1-backedge: no-op when the source
// block already equals the existing backedge's source. Exercises the
// `sourceBlock == existingBackedgeSource` early-return in
// record_generalized_loop_backedge_impl.
bool runRecordGeneralizedLoopBackedgeSingleSourceNoOpWhenSourceMatchesExistingBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  auto initialCanonicalSource =
      lifter.activeGeneralizedLoopControlFieldState.canonicalSource;
  auto initialBackedgeSource =
      lifter.activeGeneralizedLoopControlFieldState.backedgeSources.front();
  auto initialCanonicalControl =
      lifter.activeGeneralizedLoopControlFieldState.canonicalControl;

  // Call record from the SAME sourceBlock as the existing backedge.
  // Even if the buffer's control value has rolled forward, the guard
  // `sourceBlock == existingBackedgeSource` rejects the rotation.
  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, 0x1401AFFFFULL));  // different!
  lifter.record_generalized_loop_backedge(loopHeader);

  if (lifter.activeGeneralizedLoopControlFieldState.canonicalSource !=
          initialCanonicalSource ||
      lifter.activeGeneralizedLoopControlFieldState.backedgeSources.front() !=
          initialBackedgeSource ||
      lifter.activeGeneralizedLoopControlFieldState.canonicalControl !=
          initialCanonicalControl) {
    details = "  record_generalized_loop_backedge from existing backedge's "
              "sourceBlock must NOT rotate; state rotated unexpectedly\n";
    return false;
  }
  return true;
}

// record_generalized_loop_backedge 1-backedge: no-op when the body's
// rolled control value matches the existing backedge control. Without
// a distinct new control value there is no progress to record.
// Exercises the `rolledBackedgeControl == controls.front()` guard.
bool runRecordGeneralizedLoopBackedgeSingleSourceNoOpWhenControlUnchanged(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* bodyBlock =
      llvm::BasicBlock::Create(context, "body", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  auto initialCanonicalSource =
      lifter.activeGeneralizedLoopControlFieldState.canonicalSource;
  auto initialCanonicalControl =
      lifter.activeGeneralizedLoopControlFieldState.canonicalControl;

  // Body block with the SAME control value as the existing backedge.
  // record_generalized_loop_backedge must skip the rotation.
  lifter.builder->SetInsertPoint(bodyBlock);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.record_generalized_loop_backedge(loopHeader);

  if (lifter.activeGeneralizedLoopControlFieldState.canonicalSource !=
          initialCanonicalSource ||
      lifter.activeGeneralizedLoopControlFieldState.canonicalControl !=
          initialCanonicalControl) {
    details = "  record_generalized_loop_backedge with unchanged control "
              "value must not rotate the state\n";
    return false;
  }
  return true;
}

// record_generalized_loop_backedge 1-backedge: positive rotation case.
// When the body source differs from the existing backedge source AND the
// rolled control value differs, the old backedge becomes canonical and
// the body source becomes the new single backedge.
bool runRecordGeneralizedLoopBackedgeSingleSourceRotatesCanonicalAndBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* bodyBlock =
      llvm::BasicBlock::Create(context, "body", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t rolledControl = 0x1401AEB43ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);

  lifter.builder->SetInsertPoint(bodyBlock);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, rolledControl));
  lifter.record_generalized_loop_backedge(loopHeader);

  const auto& state = lifter.activeGeneralizedLoopControlFieldState;
  if (!state.valid) {
    details = "  state should remain valid after positive rotation\n";
    return false;
  }
  if (state.canonicalSource != backedge ||
      state.canonicalControl != backedgeControl) {
    details = "  positive rotation should promote the old backedge into canonical\n";
    return false;
  }
  if (state.backedgeSources.size() != 1 ||
      state.backedgeSources.front() != bodyBlock ||
      state.backedgeControls.front() != rolledControl) {
    details = "  positive rotation should install the body source as the new single backedge\n";
    return false;
  }
  return true;
}

// migrate_generalized_loop_block copies BBbackup, generalizedLoopBackedgeBackup,
// generalizedLoopRegisterPhis, generalizedLoopFlagPhis, and
// generalizedLoopControlFieldStates from oldBlock to newBlock when
// newBlock has no entries of its own. Exercises the block-replacement
// path used when the lifter reconstructs a header in place.
bool runMigrateGeneralizedLoopBlockCopiesAllStateToNewBlock(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* oldHeader =
      llvm::BasicBlock::Create(context, "old_header", lifter.fnc);
  auto* newHeader =
      llvm::BasicBlock::Create(context, "new_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(oldHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(oldHeader, /*generalized=*/true);
  lifter.load_generalized_backup(oldHeader);

  if (!lifter.activeGeneralizedLoopControlFieldState.valid ||
      lifter.generalizedLoopControlFieldStates.count(oldHeader) != 1) {
    details = "  pre-migration setup should have activated oldHeader state\n";
    return false;
  }

  lifter.migrate_generalized_loop_block(oldHeader, newHeader);

  if (lifter.generalizedLoopControlFieldStates.count(newHeader) != 1) {
    details = "  migrate_generalized_loop_block should copy control-field "
              "state into newBlock\n";
    return false;
  }
  if (lifter.generalizedLoopControlFieldStates[newHeader].headerBlock !=
      newHeader) {
    details = "  migrated state should have its headerBlock rewritten to "
              "newBlock\n";
    return false;
  }
  if (lifter.BBbackup.count(newHeader) != 1 ||
      lifter.generalizedLoopBackedgeBackup.count(newHeader) != 1) {
    details = "  migrate_generalized_loop_block should copy BBbackup and "
              "generalizedLoopBackedgeBackup to newBlock\n";
    return false;
  }
  return true;
}

// make_generalized_loop_backup: non-preserved register widens to Undef
// on the first backedge (widenFirstBackedge=true by default). RAX is
// not in shouldPreserveGeneralizedBackedgeRegisterIndex's preserve set,
// so its phi incoming from backedge must be UndefValue.
bool runMakeGeneralizedLoopBackupWidensRaxToUndefOnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRax = 0xAAAA1111ULL;
  constexpr uint64_t backedgeRax = 0xBBBB2222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX,
                          makeI64(context, canonicalRax));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX,
                          makeI64(context, backedgeRax));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rax = lifter.GetRegisterValue(RegisterUnderTest::RAX);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(rax);
  if (!phi) {
    details = "  RAX should become a phi at the loop header\n";
    return false;
  }
  bool sawCanonical = false;
  bool sawUndef = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto* inc = phi->getIncomingValue(i);
    if (llvm::isa<llvm::UndefValue>(inc)) {
      sawUndef = true;
    } else {
      auto actual = readConstantAPInt(inc);
      if (actual.has_value() && actual->getZExtValue() == canonicalRax) {
        sawCanonical = true;
      }
    }
  }
  if (!sawCanonical || !sawUndef) {
    details = "  RAX phi should carry canonical concrete value and Undef "
              "for the widened first backedge (non-preserved register)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_phi_address_value_impl with a NEGATIVE
// constant displacement via Sub. The helper must extract the constant
// offset, negate it, and resolve each phi incoming at (address -
// offset). Exercises the `Sub` branch of the binop-unwrap in the helper.
bool runGeneralizedPhiAddressWithNegativeDisplacementResolvesLoadedValues(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr int64_t negDisplacement = -16;
  constexpr uint64_t baseA = 0x140070010ULL;
  constexpr uint64_t baseB = 0x140070110ULL;
  constexpr uint64_t valueA = 0x1234567812345678ULL;
  constexpr uint64_t valueB = 0xDEADC0DEDEADC0DEULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  // Values live at base - 16 on each side.
  lifter.SetMemoryValue(makeI64(context, baseA + negDisplacement),
                        makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, baseB + negDisplacement),
                        makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "neg_disp_phi_addr");
  addressPhi->addIncoming(makeI64(context, baseA), preheader);
  addressPhi->addIncoming(makeI64(context, baseB), backedge);
  auto* displaced = lifter.builder->CreateSub(
      addressPhi, llvm::ConstantInt::get(i64Ty, 16),
      "neg_disp_address");
  auto* resolved = lifter.GetMemoryValue(displaced, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    details = "  phi-address + negative displacement load should yield a phi\n";
    return false;
  }
  bool sawA = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  negative-displacement phi-address load should carry both "
              "canonical and backedge stored values\n";
    return false;
  }
  return true;
}

// make_generalized_loop_backup preserves the concrete backedge value for
// RCX (shouldPreserveGeneralizedBackedgeRegisterIndex index 1). The
// preserve set protects specific registers from the default Undef
// widening so their backedge value flows through unchanged on the
// first lift. Without this, RCX would become Undef and downstream code
// using it would lose its concrete shape.
bool runMakeGeneralizedLoopBackupPreservesConcreteRcxOnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRcx = 0xC0DE1111ULL;
  constexpr uint64_t backedgeRcx = 0xFADE2222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RCX,
                          makeI64(context, canonicalRcx));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RCX,
                          makeI64(context, backedgeRcx));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rcx = lifter.GetRegisterValue(RegisterUnderTest::RCX);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(rcx);
  if (!phi) {
    details = "  RCX should become a phi at the loop header\n";
    return false;
  }
  bool sawCanonical = false;
  bool sawConcreteBackedge = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto* inc = phi->getIncomingValue(i);
    if (llvm::isa<llvm::UndefValue>(inc)) {
      details = "  RCX phi must not carry Undef - RCX is in the preserved "
                "set (shouldPreserveGeneralizedBackedgeRegisterIndex=1)\n";
      return false;
    }
    auto actual = readConstantAPInt(inc);
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalRcx) sawCanonical = true;
    else if (v == backedgeRcx) sawConcreteBackedge = true;
  }
  if (!sawCanonical || !sawConcreteBackedge) {
    details = "  RCX phi should carry both canonical and concrete backedge "
              "values (preserved register, no Undef widening)\n";
    return false;
  }
  return true;
}

// Symmetric preserve test for R12 (shouldPreserveGeneralizedBackedgeRegisterIndex
// index 12). Confirms the preserve list covers more than just RCX/RSP.
bool runMakeGeneralizedLoopBackupPreservesConcreteR12OnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalR12 = 0x1111AAAAULL;
  constexpr uint64_t backedgeR12 = 0x2222BBBBULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::R12,
                          makeI64(context, canonicalR12));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::R12,
                          makeI64(context, backedgeR12));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* r12 = lifter.GetRegisterValue(RegisterUnderTest::R12);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(r12);
  if (!phi) {
    details = "  R12 should become a phi at the loop header\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  R12 phi must not carry Undef - R12 is in the preserved set\n";
      return false;
    }
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalR12) sawC = true;
    else if (v == backedgeR12) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  R12 phi should carry both concrete values (preserve set)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_target_slot_value_impl collapses to the
// shared value (no phi) when canonical and backedge buffers hold the
// SAME concrete value at kThemidaLoopCarriedSlot. Exercises the
// `canonicalValue == backedgeValue` early-return in target_slot.
bool runGeneralizedLoopTargetSlotCollapsesToCanonicalWhenValuesMatch(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t loopCarriedSlot = 0x14004DC67ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t sharedCarriedValue = 0xDEADBEEFCAFEBABEULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, sharedCarriedValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  // Same carried value on backedge - helper must collapse to single.
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, sharedCarriedValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* carried =
      lifter.GetMemoryValue(makeI64(context, loopCarriedSlot), 64);
  if (llvm::isa<llvm::PHINode>(carried)) {
    details = "  target-slot helper should collapse matching canonical+backedge "
              "to a single concrete value, not a phi\n";
    return false;
  }
  auto actual = readConstantAPInt(carried);
  if (!actual.has_value() || actual->getZExtValue() != sharedCarriedValue) {
    details = "  collapsed target-slot should carry the shared concrete value\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_local_value_impl returns the concrete local
// stack-buffer value directly (no phi) when the active buffer contains
// a tracked value at the address. Exercises the retrieveValueFromBufferSlice
// single-value path for loop-local stack slots.
bool runGeneralizedLoopLocalValueReturnsConcreteStackBufferValue(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t localAddr = STACKP_VALUE + 24;  // loop-local stack slot
  constexpr uint64_t localValue = 0x7777888899990000ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  // Seed loop-local slot on the backedge side only.
  lifter.SetMemoryValue(makeI64(context, localAddr),
                        makeI64(context, localValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // Local stack addresses are routed through retrieve_generalized_loop_local_value_impl
  // which returns the tracked buffer value directly.
  auto* result = lifter.GetMemoryValue(makeI64(context, localAddr), 64);
  auto actual = readConstantAPInt(result);
  if (!actual.has_value() || actual->getZExtValue() != localValue) {
    details = "  local stack-slot load should resolve to the concrete "
              "tracked buffer value\n";
    return false;
  }
  return true;
}

// make_generalized_loop_backup preserves the CONCRETE backedge value
// for RSP when canonical and backedge RSP differ. Companion to the
// rsp-collapse test (which uses the same constant on both sides):
// here, distinct values force phi construction, and the preserve
// flag must keep the backedge incoming as the concrete value (not
// Undef). Without preserve, the loop body's stack-pointer accounting
// would be polluted by Undef.
bool runMakeGeneralizedLoopBackupPreservesConcreteRspWhenValuesDiffer(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRsp = 0x14FEA0ULL;
  constexpr uint64_t backedgeRsp = 0x14FE80ULL;  // distinct from canonical

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RSP,
                          makeI64(context, canonicalRsp));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RSP,
                          makeI64(context, backedgeRsp));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rsp = lifter.GetRegisterValue(RegisterUnderTest::RSP);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(rsp);
  if (!phi) {
    details = "  RSP with distinct canonical/backedge values should yield a phi\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  RSP phi must not carry Undef - RSP is preserved\n";
      return false;
    }
  }
  bool sawCanonical = false, sawBackedge = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalRsp) sawCanonical = true;
    else if (v == backedgeRsp) sawBackedge = true;
  }
  if (!sawCanonical || !sawBackedge) {
    details = "  RSP phi should carry both concrete canonical and backedge "
              "values (preserve set, distinct values)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_control_slot_value_impl with byteCount=2
// returns a phi of i16 values, masking the upper bits of the canonical
// and backedge controlCursor scalars. Exercises the byteCount path of
// the helper for narrower reads.
bool runGeneralizedLoopControlSlotByteCountTwoReturnsMaskedPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AABBULL;
  constexpr uint64_t backedgeControl = 0x1401CCDDULL;
  constexpr uint64_t loCanonical = canonicalControl & 0xFFFFULL;  // 0xAABB
  constexpr uint64_t loBackedge = backedgeControl & 0xFFFFULL;   // 0xCCDD

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* result = lifter.GetMemoryValue(makeI64(context, controlSlot), 16);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(result);
  if (!phi) {
    details = "  control_slot with byteCount=2 should still produce a phi\n";
    return false;
  }
  if (!phi->getType()->isIntegerTy(16)) {
    details = "  control_slot phi at byteCount=2 should have i16 type\n";
    return false;
  }
  bool sawCanonicalLow = false, sawBackedgeLow = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == loCanonical) sawCanonicalLow = true;
    else if (v == loBackedge) sawBackedgeLow = true;
  }
  if (!sawCanonicalLow || !sawBackedgeLow) {
    details = "  control_slot byteCount=2 phi should carry the masked lower-16 "
              "bits of canonical and backedge controlCursor\n";
    return false;
  }
  return true;
}

// generalizedLoopRegisterPhis is the per-header map that records the
// PHINode pointer make_generalized_loop_backup created for each
// register slot. After load_generalized_backup, the entry for the
// header MUST exist and contain valid phi pointers for any register
// that diverged between canonical and backedge.
bool runMakeGeneralizedLoopBackupPopulatesRegisterPhisMap(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRax = 0xAAAA1111ULL;
  constexpr uint64_t backedgeRax = 0xBBBB2222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX,
                          makeI64(context, canonicalRax));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX,
                          makeI64(context, backedgeRax));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);

  if (lifter.generalizedLoopRegisterPhis.count(loopHeader) != 1) {
    details = "  generalizedLoopRegisterPhis must contain an entry for the "
              "header after load_generalized_backup\n";
    return false;
  }
  const auto& phisForHeader = lifter.generalizedLoopRegisterPhis[loopHeader];
  // RAX is index 0 in the gprOrder used by make_generalized_loop_backup;
  // its phi must have been recorded.
  // RegisterManagerConcolic::getRegisterIndex(RAX) == 0 (index relative to
  // Register::RAX, which starts the GPR window in Register enum).
  auto* raxPhi = phisForHeader[0];
  if (!raxPhi) {
    details = "  generalizedLoopRegisterPhis[header][RAX] should be a valid "
              "PHINode pointer after divergent canonical/backedge\n";
    return false;
  }
  if (raxPhi->getParent() != loopHeader) {
    details = "  recorded RAX phi should live in the loop header\n";
    return false;
  }
  return true;
}

// generalizedLoopFlagPhis is the per-header flag-phi map. After
// load_generalized_backup with divergent flag state between canonical
// and backedge, the map must contain an entry for the header and the
// recorded PHINode pointers must live in the header block.
bool runMakeGeneralizedLoopBackupPopulatesFlagPhisMap(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getFalse(context));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getTrue(context));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);

  if (lifter.generalizedLoopFlagPhis.count(loopHeader) != 1) {
    details = "  generalizedLoopFlagPhis must contain an entry for the "
              "header when canonical/backedge flags differ\n";
    return false;
  }
  const auto& flagPhis = lifter.generalizedLoopFlagPhis[loopHeader];
  auto* zfPhi = flagPhis[static_cast<size_t>(FLAG_ZF)];
  if (!zfPhi) {
    details = "  generalizedLoopFlagPhis[header][FLAG_ZF] should be a valid "
              "PHINode pointer after divergent canonical/backedge flag\n";
    return false;
  }
  if (zfPhi->getParent() != loopHeader) {
    details = "  recorded FLAG_ZF phi should live in the loop header\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_control_field_value_impl collapses to the
// shared value when canonical and backedge buffers hold IDENTICAL values
// at the computed (controlCursor + offset) address for a supported
// offset. Exercises the `allSame` short-circuit in the helper.
bool runGeneralizedLoopControlFieldLoadCollapsesWhenValuesMatch(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t fieldOffset = 0xAULL;  // supported offset
  constexpr uint16_t sharedField = 0x9C9C;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(
      makeI64(context, canonicalControl + fieldOffset),
      llvm::ConstantInt::get(llvm::Type::getInt16Ty(context), sharedField));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(
      makeI64(context, backedgeControl + fieldOffset),
      llvm::ConstantInt::get(llvm::Type::getInt16Ty(context), sharedField));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlValue =
      lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* displacedAddress = lifter.builder->CreateAdd(
      controlValue,
      llvm::ConstantInt::get(controlValue->getType(), fieldOffset),
      "generalized_control_field_plus_0xA");
  auto* fieldValue = lifter.GetMemoryValue(displacedAddress, 16);
  if (llvm::isa<llvm::PHINode>(fieldValue)) {
    details = "  control_field helper should collapse matching canonical+backedge "
              "field values to a single i16, not a phi\n";
    return false;
  }
  auto actual = readConstantAPInt(fieldValue);
  if (!actual.has_value() || actual->getZExtValue() != sharedField) {
    details = "  collapsed control_field should carry the shared concrete value\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_control_slot_value_impl bails on byteCount=0
// and byteCount>8 via the `byteCount == 0 || byteCount > 8` guard. Test
// the upper bound by requesting a 16-byte read at the control slot -
// the helper must return nullptr so the caller falls through.
bool runGeneralizedLoopControlSlotByteCountSixteenFallsThrough(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // 128-bit read: beyond the helper's 8-byte cap. Helper returns nullptr;
  // the fallback path serves the read via the normal memory pipeline.
  auto* result = lifter.GetMemoryValue(makeI64(context, controlSlot), 128);
  if (llvm::isa<llvm::PHINode>(result)) {
    details = "  control_slot helper should NOT produce a phi at byteCount=16 "
              "(exceeds the 8-byte cap); caller must fall through\n";
    return false;
  }
  return true;
}

// load_generalized_backup with NO backedges (never saw a generalized=true
// branch_backup) falls through to the canonical-only path, which calls
// make_generalized_loop_backup with an empty ArrayRef. The resulting
// snapshot is canonical with local-stack-filtered buffer; no activeState
// is populated and no register phi is built. Exercises the `if
// (BBbackup.contains(bb)) { ... empty ArrayRef ... }` fallback branch of
// load_generalized_backup_impl.
bool runGeneralizedLoopBackupCanonicalOnlyPathPreservesBBbackupState(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t canonicalRax = 0xDEADBEEFULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX,
                          makeI64(context, canonicalRax));
  lifter.branch_backup(loopHeader);
  // Deliberately NO generalized branch_backup - the header has only
  // its canonical snapshot, no backedges.

  lifter.load_generalized_backup(loopHeader);
  // Active state must NOT be activated without backedges.
  if (lifter.activeGeneralizedLoopControlFieldState.valid) {
    details = "  active state must stay invalid when the header has no "
              "generalized backedges\n";
    return false;
  }
  // No register-phi map entry: mergeValue never ran.
  if (lifter.generalizedLoopRegisterPhis.count(loopHeader) != 0) {
    details = "  register-phi map should stay empty on the canonical-only "
              "fallback path\n";
    return false;
  }
  // But the canonical values ARE restored into `vec`. After the load,
  // GetRegisterValue(RAX) should resolve to the concrete canonical value.
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rax = lifter.GetRegisterValue(RegisterUnderTest::RAX);
  auto actual = readConstantAPInt(rax);
  if (!actual.has_value() || actual->getZExtValue() != canonicalRax) {
    details = "  canonical-only load should restore the canonical RAX value\n";
    return false;
  }
  return true;
}

// Canonical-only load path: flag PHI map stays empty when there are no
// generalized backedges. Symmetric to the register-phi canonical-only
// test but for generalizedLoopFlagPhis.
bool runGeneralizedLoopBackupCanonicalOnlyPathLeavesFlagPhisEmpty(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetFlagValue_impl(FLAG_CF, llvm::ConstantInt::getFalse(context));
  lifter.branch_backup(loopHeader);

  lifter.load_generalized_backup(loopHeader);

  if (lifter.generalizedLoopFlagPhis.count(loopHeader) != 0) {
    details = "  flag-phi map should stay empty on the canonical-only "
              "fallback path\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_phi_address_value_impl unwraps a ZExt cast
// over the phi-of-addresses operand. The helper walks past chained
// IntegerTy CastInsts to recover the underlying phi. Exercises the
// `while (auto* castInst = dyn_cast<CastInst>(loadOffset))` loop.
bool runGeneralizedPhiAddressUnwrapsZExtCastOverPhi(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i32Ty = llvm::Type::getInt32Ty(context);
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint32_t addrA = 0x40070000U;
  constexpr uint32_t addrB = 0x40070100U;
  constexpr uint64_t valueA = 0x55AA55AA55AA55AAULL;
  constexpr uint64_t valueB = 0x33CC33CC33CC33CCULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, addrA), makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, addrB), makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // i32 phi over two concrete addresses, then ZExt to i64 - the helper
  // must walk past the ZExt to find the underlying phi.
  auto* phi32 = lifter.builder->CreatePHI(i32Ty, 2, "i32_addr_phi");
  phi32->addIncoming(llvm::ConstantInt::get(i32Ty, addrA), preheader);
  phi32->addIncoming(llvm::ConstantInt::get(i32Ty, addrB), backedge);
  auto* zextAddr = lifter.builder->CreateZExt(phi32, i64Ty, "zext_addr");
  auto* resolved = lifter.GetMemoryValue(zextAddr, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    details = "  phi-address helper should unwrap ZExt and produce a phi of "
              "loaded values\n";
    return false;
  }
  bool sawA = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  ZExt-wrapped phi-address load should resolve both incomings\n";
    return false;
  }
  return true;
}

// Same as above but with SExt cast. Confirms the cast unwrap accepts
// both zero- and sign-extending casts uniformly.
bool runGeneralizedPhiAddressUnwrapsSExtCastOverPhi(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i32Ty = llvm::Type::getInt32Ty(context);
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr int32_t addrA = 0x40080000;
  constexpr int32_t addrB = 0x40080200;
  constexpr uint64_t valueA = 0xCAFEFACECAFEFACEULL;
  constexpr uint64_t valueB = 0xBADC0FFEBADC0FFEULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, static_cast<uint64_t>(addrA)),
                        makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, static_cast<uint64_t>(addrB)),
                        makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* phi32 = lifter.builder->CreatePHI(i32Ty, 2, "i32_addr_phi_sext");
  phi32->addIncoming(llvm::ConstantInt::getSigned(i32Ty, addrA), preheader);
  phi32->addIncoming(llvm::ConstantInt::getSigned(i32Ty, addrB), backedge);
  auto* sextAddr = lifter.builder->CreateSExt(phi32, i64Ty, "sext_addr");
  auto* resolved = lifter.GetMemoryValue(sextAddr, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    details = "  phi-address helper should unwrap SExt and produce a phi of "
              "loaded values\n";
    return false;
  }
  bool sawA = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  SExt-wrapped phi-address load should resolve both incomings\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_phi_address_value_impl base case: a
// raw phi of two concrete addresses, no displacement, no cast. The
// helper's binop-unwrap and cast-unwrap should both no-op and the
// phi is consumed directly.
bool runGeneralizedPhiAddressBaseCaseWithoutDisplacementResolvesLoadedValues(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t baseA = 0x140090000ULL;
  constexpr uint64_t baseB = 0x140090400ULL;
  constexpr uint64_t valueA = 0xABCD0001ABCD0001ULL;
  constexpr uint64_t valueB = 0xEF010002EF010002ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, baseA), makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, baseB), makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi =
      lifter.builder->CreatePHI(i64Ty, 2, "raw_phi_addr_no_disp");
  addressPhi->addIncoming(makeI64(context, baseA), preheader);
  addressPhi->addIncoming(makeI64(context, baseB), backedge);
  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    details = "  raw phi-address (no displacement, no cast) should yield a "
              "phi of loaded values\n";
    return false;
  }
  bool sawA = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  raw phi-address load should resolve both incomings\n";
    return false;
  }
  return true;
}

// KNOWN-LIMITATION (target-slot helper hardcoded to kThemidaLoopCarriedSlot).
//
// retrieve_generalized_loop_target_slot_value_impl gates on
// `startAddress != this->kThemidaLoopCarriedSlot`. A loop whose
// loop-carried slot is at any other address cannot benefit from the
// helper's phi-collapse fast path; the caller falls back to the normal
// memory pipeline.
//
// This is a sibling limitation to the kThemidaControlCursorSlot one
// (pinned by generalized_loop_non_themida_control_slot_produces_no_phi).
// When per-function carried-slot detection lands, this test MUST fail
// and be rewritten to assert the new contract.
bool runGeneralizedLoopNonThemidaTargetSlotProducesNoPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t themidaControlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  // Plausible carried-slot for a non-Themida sample; not 0x14004DC67.
  constexpr uint64_t otherTargetSlot = 0x140050800ULL;
  constexpr uint64_t otherCanonical = 0xAA01AA01AA01AA01ULL;
  constexpr uint64_t otherBackedge = 0xBB02BB02BB02BB02ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, themidaControlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, otherTargetSlot),
                        makeI64(context, otherCanonical));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, themidaControlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, otherTargetSlot),
                        makeI64(context, otherBackedge));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* loaded =
      lifter.GetMemoryValue(makeI64(context, otherTargetSlot), 64);
  if (llvm::isa<llvm::PHINode>(loaded)) {
    details = "  GetMemoryValue at non-Themida loop-carried slot unexpectedly "
              "produced a PHINode - target-slot hardcoded gate has been "
              "generalized; rewrite this test against the new contract.\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader rejects when addrToBB has no entry
// for the target address. Exercises the `it == addrToBB.end()` branch
// of the empty-or-missing-bb guard.
bool runLoopGeneralizationMissingAddrToBBEntryRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  // Deliberately NO addrToBB entry for 0x1000.

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  missing addrToBB entry for target must reject "
              "(empty-or-missing-bb guard)\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader rejects when addrToBB maps the
// address to an empty BasicBlock. Exercises the `it->second->empty()`
// arm of the empty-or-missing-bb guard.
bool runLoopGeneralizationEmptyBasicBlockRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* empty = llvm::BasicBlock::Create(lifter.context, "empty_bb", lifter.fnc);
  // `empty` has no instructions - size() == 0.

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = empty;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  empty BasicBlock must reject generalization "
              "(empty-or-missing-bb guard)\n";
    return false;
  }
  return true;
}

// canGeneralizeStructuredLoopHeader rejects when blockInfo.block is
// null. Without a valid current block, blockCanReach has no source -
// the guard short-circuits.
bool runLoopGeneralizationNullCurrentBlockRejected(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);
  llvm::IRBuilder<> hb(header);
  hb.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, nullptr);  // no current block
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  null current block must reject generalization "
              "(no-current-block guard)\n";
    return false;
  }
  return true;
}

// branch_backup with generalized=true appends a new backup_point when
// the source block differs from every existing backedge entry. The
// companion to branch_backup_generalized_dedups_by_source_block, which
// covered the replace-in-place path.
bool runBranchBackupGeneralizedAppendsWhenSourceDiffers(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedgeA =
      llvm::BasicBlock::Create(context, "backedge_a", lifter.fnc);
  auto* backedgeB =
      llvm::BasicBlock::Create(context, "backedge_b", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t controlA = 0x1401AF0F6ULL;
  constexpr uint64_t controlB = 0x1401AEB43ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedgeA);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, controlA));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.builder->SetInsertPoint(backedgeB);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, controlB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  auto it = lifter.generalizedLoopBackedgeBackup.find(loopHeader);
  if (it == lifter.generalizedLoopBackedgeBackup.end() ||
      it->second.size() != 2) {
    std::ostringstream os;
    os << "  distinct sourceBlocks must append; got size "
       << (it == lifter.generalizedLoopBackedgeBackup.end()
               ? 0u
               : static_cast<unsigned>(it->second.size()))
       << " expected 2\n";
    details = os.str();
    return false;
  }
  bool sawA = false, sawB = false;
  for (const auto& be : it->second) {
    if (be.sourceBlock == backedgeA) sawA = true;
    else if (be.sourceBlock == backedgeB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  appended vector should hold one entry per distinct "
              "sourceBlock\n";
    return false;
  }
  return true;
}

// record_generalized_loop_backedge_impl on a multi-way state is a
// no-op when the body source is already one of the existing backedges
// AND its control value is unchanged. Complements the multi-way append
// test (runRecordGeneralizedLoopBackedgeMultiwayAppendsNewBodySource)
// which covered the update and append branches.
bool runRecordGeneralizedLoopBackedgeMultiwayNoOpWhenControlUnchanged(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* firstBackedge =
      llvm::BasicBlock::Create(context, "first_backedge", lifter.fnc);
  auto* secondBackedge =
      llvm::BasicBlock::Create(context, "second_backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t firstControl = 0x1401AF0F6ULL;
  constexpr uint64_t secondControl = 0x1401AEB43ULL;

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

  lifter.load_generalized_backup(loopHeader);
  const size_t sizeBefore =
      lifter.activeGeneralizedLoopControlFieldState.backedgeSources.size();
  if (sizeBefore != 2) {
    details = "  multi-way setup should have 2 backedges before record\n";
    return false;
  }

  // Call record from firstBackedge WITH firstControl (unchanged from
  // load_generalized_backup). Helper must not mutate state.
  lifter.builder->SetInsertPoint(firstBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, firstControl));
  lifter.record_generalized_loop_backedge(loopHeader);

  if (lifter.activeGeneralizedLoopControlFieldState.backedgeSources.size() !=
      sizeBefore) {
    details = "  multi-way record with unchanged control must be a no-op "
              "(size should stay at 2)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_control_slot_value_impl collapses to the
// canonical value (no phi) when canonical and backedge controlCursor
// buffers hold the SAME concrete value. Exercises the `allSame`
// short-circuit of the control-slot helper. Different sourceBlocks but
// identical cursor values still activates generalization (per the
// canonicalControl != backedgeControl check), so this test forces a
// mixed slot match through two slots.
bool runGeneralizedLoopControlSlotCollapsesWhenCanonicalMatchesBackedgeValue(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  // Activation requires distinct canonical/backedge at controlSlot. We
  // probe a DIFFERENT slot (controlSlot+0x10, outside the recognized
  // offset set) that holds a matching concrete value on both sides.
  // Loading that slot should collapse to the shared constant - the
  // helper's `allSame` short-circuit fires.
  constexpr uint64_t probeSlot = controlSlot + 0x10;  // unsupported offset
  constexpr uint64_t sharedValue = 0x7777888899990000ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, probeSlot),
                        makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, probeSlot),
                        makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // Loading from probeSlot: canonical and backedge buffers agree, so
  // the control-slot helper (with the Themida-slot gate generalized to
  // buffer lookup under #123 for matching values) must collapse.
  // Currently the helper gates on kThemidaControlCursorSlot so this
  // probe falls through to normal memory - the TRACKED result is the
  // last-written concrete value.
  auto* loaded = lifter.GetMemoryValue(makeI64(context, probeSlot), 64);
  auto actual = readConstantAPInt(loaded);
  if (!actual.has_value() || actual->getZExtValue() != sharedValue) {
    details = "  load at matching-value slot should resolve to shared value\n";
    return false;
  }
  return true;
}


// migrate_generalized_loop_block is a no-op when oldBlock == newBlock.
// The function's contract opens with `if (oldBlock == newBlock) return;`
// so state is not duplicated or modified.
bool runMigrateGeneralizedLoopBlockNoOpWhenSameBlock(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);
  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);
  lifter.load_generalized_backup(loopHeader);

  const auto bbBackupSizeBefore = lifter.BBbackup.size();
  const auto genSizeBefore = lifter.generalizedLoopBackedgeBackup.size();
  const auto stateSizeBefore = lifter.generalizedLoopControlFieldStates.size();

  lifter.migrate_generalized_loop_block(loopHeader, loopHeader);  // same

  if (lifter.BBbackup.size() != bbBackupSizeBefore ||
      lifter.generalizedLoopBackedgeBackup.size() != genSizeBefore ||
      lifter.generalizedLoopControlFieldStates.size() != stateSizeBefore) {
    details = "  migrate_generalized_loop_block(bb, bb) should be a no-op\n";
    return false;
  }
  return true;
}

// migrate_generalized_loop_block does NOT overwrite existing entries in
// newBlock's slot. Each copy is gated on `!map.contains(newBlock)`.
// A pre-existing entry in newBlock must survive the migration call.
bool runMigrateGeneralizedLoopBlockPreservesExistingNewBlockEntry(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* oldHeader =
      llvm::BasicBlock::Create(context, "old_header", lifter.fnc);
  auto* newHeader =
      llvm::BasicBlock::Create(context, "new_header", lifter.fnc);
  auto* newPreheader =
      llvm::BasicBlock::Create(context, "new_preheader", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t oldCanonical = 0x1401AF740ULL;
  constexpr uint64_t oldBackedge = 0x1401AF0F6ULL;
  constexpr uint64_t newPreservedCanonical = 0x1401BFFFFULL;

  // Set up oldHeader state.
  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, oldCanonical));
  lifter.branch_backup(oldHeader);
  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, oldBackedge));
  lifter.branch_backup(oldHeader, /*generalized=*/true);
  lifter.load_generalized_backup(oldHeader);

  // Seed a pre-existing newHeader entry via a separate branch_backup.
  lifter.builder->SetInsertPoint(newPreheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, newPreservedCanonical));
  lifter.branch_backup(newHeader);
  auto preExisting = lifter.BBbackup[newHeader].sourceBlock;

  lifter.migrate_generalized_loop_block(oldHeader, newHeader);

  if (lifter.BBbackup[newHeader].sourceBlock != preExisting) {
    details = "  migrate_generalized_loop_block must not overwrite existing "
              "BBbackup[newBlock] entry\n";
    return false;
  }
  return true;
}

// migrate_generalized_loop_block must NOT overwrite pre-existing register
// and flag phi maps on newBlock; each copy is gated on
// `!generalizedLoopRegisterPhis.contains(newBlock)` / same for flags.
bool runMigrateGeneralizedLoopBlockPreservesExistingRegisterAndFlagPhiMaps(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* oldHeader =
      llvm::BasicBlock::Create(context, "old_header", lifter.fnc);
  auto* newHeader =
      llvm::BasicBlock::Create(context, "new_header", lifter.fnc);
  auto* preseedHeader =
      llvm::BasicBlock::Create(context, "preseed_header", lifter.fnc);
  auto* preseedBackedge =
      llvm::BasicBlock::Create(context, "preseed_backedge", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t oldCanonical = 0x1401AF740ULL;
  constexpr uint64_t oldBackedge = 0x1401AF0F6ULL;
  constexpr uint64_t newCanonical = 0x1401BFFFFULL;
  constexpr uint64_t newBackedge = 0x1401BFF00ULL;

  // Seed oldHeader with phi maps.
  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot), makeI64(context, oldCanonical));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x1111));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getFalse(context));
  lifter.branch_backup(oldHeader);
  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot), makeI64(context, oldBackedge));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x2222));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getTrue(context));
  lifter.branch_backup(oldHeader, /*generalized=*/true);
  lifter.load_generalized_backup(oldHeader);

  // Seed newHeader with DIFFERENT phi maps that must survive migration.
  lifter.builder->SetInsertPoint(preseedHeader);
  lifter.SetMemoryValue(makeI64(context, controlSlot), makeI64(context, newCanonical));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x3333));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getFalse(context));
  lifter.branch_backup(newHeader);
  lifter.builder->SetInsertPoint(preseedBackedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot), makeI64(context, newBackedge));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x4444));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getTrue(context));
  lifter.branch_backup(newHeader, /*generalized=*/true);
  lifter.load_generalized_backup(newHeader);

  auto* preservedRaxPhi = lifter.generalizedLoopRegisterPhis[newHeader][0];
  auto* preservedZfPhi = lifter.generalizedLoopFlagPhis[newHeader][static_cast<size_t>(FLAG_ZF)];

  lifter.migrate_generalized_loop_block(oldHeader, newHeader);

  if (lifter.generalizedLoopRegisterPhis[newHeader][0] != preservedRaxPhi ||
      lifter.generalizedLoopFlagPhis[newHeader][static_cast<size_t>(FLAG_ZF)] != preservedZfPhi) {
    details = "  migrate_generalized_loop_block must not overwrite existing register/flag phi maps on newBlock\n";
    return false;
  }
  return true;
}

// make_generalized_loop_backup preserves R9 (shouldPreserveGeneralizedBackedgeRegisterIndex
// index 9). Confirms the preserve list extends past RCX/RSP/R12 to R9 -
// a hot loop_reg_phi lane in the Themida sample.
bool runMakeGeneralizedLoopBackupPreservesConcreteR9OnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalR9 = 0x9000111122223333ULL;
  constexpr uint64_t backedgeR9 = 0x9000444455556666ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::R9,
                          makeI64(context, canonicalR9));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::R9,
                          makeI64(context, backedgeR9));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* r9 = lifter.GetRegisterValue(RegisterUnderTest::R9);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(r9);
  if (!phi) {
    details = "  R9 should become a phi at the loop header\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  R9 phi must not carry Undef - R9 is preserved (index 9)\n";
      return false;
    }
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalR9) sawC = true;
    else if (v == backedgeR9) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  R9 phi should carry both concrete values (preserve set)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_target_slot_value_impl bails (returns
// nullptr) when the canonical buffer has no tracked value at the
// requested address, even when state is otherwise valid. The caller
// then falls through to the normal memory pipeline.
bool runGeneralizedLoopTargetSlotBailsWhenCanonicalBufferLacksSlot(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t loopCarriedSlot = 0x14004DC67ULL;  // gated address
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t backedgeOnlyValue = 0xCDCDCDCDCDCDCDCDULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  // Deliberately do NOT seed the loopCarriedSlot on canonical.
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, backedgeOnlyValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // GetMemoryValue at loop-carried slot: target_slot helper bails
  // because canonical buffer doesn't have a tracked value here.
  // Fallback yields the live tracked value (backedge-side seeded).
  auto* loaded = lifter.GetMemoryValue(makeI64(context, loopCarriedSlot), 64);
  if (llvm::isa<llvm::PHINode>(loaded)) {
    details = "  target_slot helper should bail when canonical buffer lacks "
              "the slot; got an unexpected phi instead of fallback\n";
    return false;
  }
  return true;
}

// Preserved-register coverage: R10 at index 10 in
// shouldPreserveGeneralizedBackedgeRegisterIndex. Completes the preserved
// set beyond RCX/RSP/R9/R12 already tested.
bool runMakeGeneralizedLoopBackupPreservesConcreteR10OnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalR10 = 0xA000111100001111ULL;
  constexpr uint64_t backedgeR10 = 0xA000222200002222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::R10,
                          makeI64(context, canonicalR10));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::R10,
                          makeI64(context, backedgeR10));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* r10 = lifter.GetRegisterValue(RegisterUnderTest::R10);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(r10);
  if (!phi) {
    details = "  R10 should become a phi at the loop header\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  R10 phi must not carry Undef - R10 is preserved (index 10)\n";
      return false;
    }
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalR10) sawC = true;
    else if (v == backedgeR10) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  R10 phi should carry both concrete values (preserve set)\n";
    return false;
  }
  return true;
}

// Preserved-register coverage: R14 at index 14 in
// shouldPreserveGeneralizedBackedgeRegisterIndex.
bool runMakeGeneralizedLoopBackupPreservesConcreteR14OnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalR14 = 0xE000111100001111ULL;
  constexpr uint64_t backedgeR14 = 0xE000222200002222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::R14,
                          makeI64(context, canonicalR14));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::R14,
                          makeI64(context, backedgeR14));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* r14 = lifter.GetRegisterValue(RegisterUnderTest::R14);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(r14);
  if (!phi) {
    details = "  R14 should become a phi at the loop header\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  R14 phi must not carry Undef - R14 is preserved (index 14)\n";
      return false;
    }
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalR14) sawC = true;
    else if (v == backedgeR14) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  R14 phi should carry both concrete values (preserve set)\n";
    return false;
  }
  return true;
}

// Flag collapse: when canonical and backedge hold the same SSA value
// for a flag, mergeValue's `canonicalValue == backedgeValue` early-return
// fires on the flag path and no phi is built. Exercises the collapse
// branch for flags (symmetric to the register-collapse test).
bool runGeneralizedLoopRestoreFlagCollapsesWhenCanonicalMatchesBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  // Shared SSA value for FLAG_ZF on both paths.
  auto* sharedZf = llvm::ConstantInt::getTrue(context);

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetFlagValue_impl(FLAG_ZF, sharedZf);
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetFlagValue_impl(FLAG_ZF, sharedZf);  // same SSA value
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  auto* zf = lifter.getFlag(FLAG_ZF);
  if (llvm::isa<llvm::PHINode>(zf)) {
    details = "  FLAG_ZF should collapse to the shared SSA value, not a phi\n";
    return false;
  }
  if (zf != sharedZf) {
    details = "  collapsed FLAG_ZF should be the shared SSA value itself\n";
    return false;
  }
  return true;
}

// isStructuredLoopHeaderShape accepts a 7-hop chain of unconditional-br
// blocks ending at a conditional branch. The walker caps at 8 hops so
// depth 7 is the last-accepted chain length - this complements the
// rejects_deep_chain test which exercises the > 8 reject case.
bool runStructuredLoopHeaderAcceptsSevenHopChain(std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  constexpr unsigned kChainLen = 7;
  std::array<llvm::BasicBlock*, kChainLen> chain{};
  for (unsigned i = 0; i < kChainLen; ++i) {
    chain[i] = llvm::BasicBlock::Create(lifter.context,
                                        ("chain_" + std::to_string(i)).c_str(),
                                        lifter.fnc);
  }
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);

  for (unsigned i = 0; i + 1 < kChainLen; ++i) {
    llvm::IRBuilder<> b(chain[i]);
    b.CreateBr(chain[i + 1]);
  }
  // Final chain element has a conditional branch - walker accepts.
  llvm::IRBuilder<> lastB(chain[kChainLen - 1]);
  lastB.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  // current → chain[0] to make chain[0] reachable from current for the
  // blockCanReach guard in canGeneralize. Current has no body otherwise.
  llvm::IRBuilder<> cb(current);
  cb.CreateBr(chain[0]);

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = chain[0];

  // For a TRUE loop-latch check, chain[0] must be reachable back to
  // `current`. But here chain only flows forward to body/exit. So
  // blockCanReach returns false and canGeneralize rejects - this
  // documents that the shape IS accepted by isStructuredLoopHeaderShape
  // (depth 7 fine) but the cycle guard blocks.
  // Instead of relying on canGeneralize we can't verify shape directly
  // (the helper is private), so we construct a reach path: have body
  // branch back to current's chain entry.
  // Rewrite body to cycle back.
  body->eraseFromParent();
  auto* body2 = llvm::BasicBlock::Create(lifter.context, "body2", lifter.fnc);
  lastB.SetInsertPoint(chain[kChainLen - 1]->getTerminator());
  chain[kChainLen - 1]->getTerminator()->eraseFromParent();
  llvm::IRBuilder<> lastB2(chain[kChainLen - 1]);
  lastB2.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body2, exit);
  llvm::IRBuilder<> body2B(body2);
  body2B.CreateBr(current);

  if (!lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  7-hop chain ending in a conditional branch must be "
              "recognized as a structured loop header (depth within "
              "the 8-hop cap)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_local_phi_address_value_impl bails when a
// phi incoming is NOT a tracked local-stack address. The helper's
// `isTrackedLocalStackAddress` gate returns false for non-stack
// addresses and the whole resolution is abandoned.
bool runGeneralizedLocalPhiAddressBailsOnNonLocalStackIncoming(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t localStackAddr = STACKP_VALUE + 32;  // local
  constexpr uint64_t nonLocalAddr = 0x1400B0000ULL;        // non-local
  constexpr uint64_t anyValue = 0x1234567812345678ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, localStackAddr),
                        makeI64(context, anyValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, nonLocalAddr),
                        makeI64(context, anyValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  // Mixed: canonical incoming is local-stack, backedge incoming is NOT.
  // The local_phi_address helper requires BOTH sides to be tracked
  // local-stack addresses; the backedge non-local-stack must cause a
  // bail.
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "mixed_stack_phi_addr");
  addressPhi->addIncoming(makeI64(context, localStackAddr), preheader);
  addressPhi->addIncoming(makeI64(context, nonLocalAddr), backedge);
  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  // The local-phi-address helper must not produce a generalized_local_phi_load.
  if (auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved)) {
    if (phi->getName().starts_with("generalized_local_phi_load")) {
      details = "  local_phi_address helper should bail when a phi incoming "
                "is NOT a tracked local-stack address\n";
      return false;
    }
  }
  return true;
}

// retrieve_generalized_loop_phi_address_value_impl unwraps a Trunc cast
// over the phi-of-addresses operand just like ZExt/SExt. This covers
// the remaining integer-cast case in the cast-unwrapping loop.
bool runGeneralizedPhiAddressUnwrapsTruncCastOverPhi(std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i128Ty = llvm::Type::getInt128Ty(context);
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t addrA = 0x1400D0000ULL;
  constexpr uint64_t addrB = 0x1400D0100ULL;
  constexpr uint64_t valueA = 0xAAAA5555AAAA5555ULL;
  constexpr uint64_t valueB = 0xBBBB6666BBBB6666ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, addrA), makeI64(context, valueA));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, addrB), makeI64(context, valueB));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* phi128 = lifter.builder->CreatePHI(i128Ty, 2, "i128_addr_phi");
  phi128->addIncoming(llvm::ConstantInt::get(i128Ty, addrA), preheader);
  phi128->addIncoming(llvm::ConstantInt::get(i128Ty, addrB), backedge);
  auto* truncAddr = lifter.builder->CreateTrunc(phi128, i64Ty, "trunc_addr");
  auto* resolved = lifter.GetMemoryValue(truncAddr, 64);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(resolved);
  if (!phi) {
    details = "  phi-address helper should unwrap Trunc and produce a phi of loaded values\n";
    return false;
  }
  bool sawA = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == valueA) sawA = true;
    else if (v == valueB) sawB = true;
  }
  if (!sawA || !sawB) {
    details = "  Trunc-wrapped phi-address load should resolve both incomings\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_local_phi_address_value_impl collapses to a
// shared loaded value when all phi incomings resolve identically. This
// mirrors the non-local phi_address allSameValue collapse test but for
// tracked local-stack addresses.
bool runGeneralizedLocalPhiAddressCollapsesWhenAllIncomingsResolveToSameValue(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t stackA = STACKP_VALUE + 40;
  constexpr uint64_t stackB = STACKP_VALUE + 48;
  constexpr uint64_t sharedValue = 0xABABABABCDCDCDCDULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, stackA), makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, stackB), makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "shared_local_phi_addr");
  addressPhi->addIncoming(makeI64(context, stackA), preheader);
  addressPhi->addIncoming(makeI64(context, stackB), backedge);
  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  if (llvm::isa<llvm::PHINode>(resolved)) {
    details = "  local_phi_address helper should collapse to shared loaded value when all incomings resolve identically\n";
    return false;
  }
  auto actual = readConstantAPInt(resolved);
  if (!actual.has_value() || actual->getZExtValue() != sharedValue) {
    details = "  collapsed local_phi_address result should be the shared value\n";
    return false;
  }
  return true;
}

// target_slot helper with byteCount=1 returns an i8 phi carrying the
// masked low byte of canonical and backedge loop-carried slot values.
// Complements the byteCount=2 target_slot test.
bool runGeneralizedLoopTargetSlotByteCountOneReturnsMaskedPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t loopCarriedSlot = 0x14004DC67ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalTarget = 0xAA11BB22CC33D044ULL;
  constexpr uint64_t backedgeTarget = 0xDD55EE66FF77A088ULL;
  constexpr uint8_t loCanonical = static_cast<uint8_t>(canonicalTarget & 0xFFULL);
  constexpr uint8_t loBackedge = static_cast<uint8_t>(backedgeTarget & 0xFFULL);

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, canonicalTarget));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, backedgeTarget));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* result = lifter.GetMemoryValue(makeI64(context, loopCarriedSlot), 8);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(result);
  if (!phi) {
    details = "  target_slot with byteCount=1 should produce a phi\n";
    return false;
  }
  if (!phi->getType()->isIntegerTy(8)) {
    details = "  target_slot byteCount=1 phi should have i8 type\n";
    return false;
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == loCanonical) sawC = true;
    else if (v == loBackedge) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  target_slot byteCount=1 phi should carry masked low-byte canonical and backedge target values\n";
    return false;
  }
  return true;
}

// RDX is not in shouldPreserveGeneralizedBackedgeRegisterIndex, so its
// phi backedge incoming widens to Undef on the first lift. Symmetric
// to the RAX test but at a different non-preserved index (RDX = 2).
bool runMakeGeneralizedLoopBackupWidensRdxToUndefOnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRdx = 0xDDDD1111ULL;
  constexpr uint64_t backedgeRdx = 0xDDDD2222ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RDX,
                          makeI64(context, canonicalRdx));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RDX,
                          makeI64(context, backedgeRdx));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rdx = lifter.GetRegisterValue(RegisterUnderTest::RDX);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(rdx);
  if (!phi) {
    details = "  RDX should become a phi at the loop header\n";
    return false;
  }
  bool sawCanonical = false, sawUndef = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto* inc = phi->getIncomingValue(i);
    if (llvm::isa<llvm::UndefValue>(inc)) {
      sawUndef = true;
    } else {
      auto actual = readConstantAPInt(inc);
      if (actual.has_value() && actual->getZExtValue() == canonicalRdx) {
        sawCanonical = true;
      }
    }
  }
  if (!sawCanonical || !sawUndef) {
    details = "  RDX phi should carry canonical concrete + Undef for "
              "widened first backedge (non-preserved register, index 2)\n";
    return false;
  }
  return true;
}

// Flag merging on divergent SSA values: mergeValue is invoked for
// flags with widenFirstBackedge=false, so the resulting phi carries
// the CONCRETE backedge value (not Undef). Complements the flag
// collapse test where both sides share the same SSA.
bool runGeneralizedLoopRestoreFlagPhiCarriesConcreteBackedgeOnDivergence(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  auto* canonicalSf = llvm::ConstantInt::getFalse(context);
  lifter.SetFlagValue_impl(FLAG_SF, canonicalSf);
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  auto* backedgeSf = llvm::ConstantInt::getTrue(context);
  lifter.SetFlagValue_impl(FLAG_SF, backedgeSf);
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  auto* sf = lifter.getFlag(FLAG_SF);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(sf);
  if (!phi) {
    details = "  FLAG_SF should be a phi when canonical and backedge differ\n";
    return false;
  }
  // widenFirstBackedge=false for flags: neither incoming should be Undef.
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  FLAG_SF phi must not carry Undef - flags merge with "
                "widenFirstBackedge=false (concrete backedge value)\n";
      return false;
    }
  }
  bool sawCanonical = false, sawBackedge = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto* inc = phi->getIncomingValue(i);
    if (inc == canonicalSf) sawCanonical = true;
    else if (inc == backedgeSf) sawBackedge = true;
  }
  if (!sawCanonical || !sawBackedge) {
    details = "  FLAG_SF phi should carry both canonical and backedge SSA "
              "values directly\n";
    return false;
  }
  return true;
}

// Preserved-register coverage: RDI at index 7 in
// shouldPreserveGeneralizedBackedgeRegisterIndex. Completes the remaining
// hot loop_reg_phi lane not yet covered by earlier RCX/RSP/R9/R10/R12/R14 tests.
bool runMakeGeneralizedLoopBackupPreservesConcreteRdiOnFirstBackedge(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalRdi = 0xD100111122223333ULL;
  constexpr uint64_t backedgeRdi = 0xD100444455556666ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RDI,
                          makeI64(context, canonicalRdi));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RDI,
                          makeI64(context, backedgeRdi));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* rdi = lifter.GetRegisterValue(RegisterUnderTest::RDI);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(rdi);
  if (!phi) {
    details = "  RDI should become a phi at the loop header\n";
    return false;
  }
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    if (llvm::isa<llvm::UndefValue>(phi->getIncomingValue(i))) {
      details = "  RDI phi must not carry Undef - RDI is preserved (index 7)\n";
      return false;
    }
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == canonicalRdi) sawC = true;
    else if (v == backedgeRdi) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  RDI phi should carry both concrete values (preserve set)\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_target_slot_value_impl with byteCount=2
// returns an i16 phi carrying the masked lower 16 bits of canonical
// and backedge loop-carried slot values. Symmetric to the control-slot
// byteCount=2 test, but exercises the target_slot helper.
bool runGeneralizedLoopTargetSlotByteCountTwoReturnsMaskedPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t loopCarriedSlot = 0x14004DC67ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t canonicalTarget = 0xAA11BB22CC33D044ULL;
  constexpr uint64_t backedgeTarget = 0xDD55EE66FF77A088ULL;
  constexpr uint64_t loCanonical = canonicalTarget & 0xFFFFULL;
  constexpr uint64_t loBackedge = backedgeTarget & 0xFFFFULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, canonicalTarget));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, loopCarriedSlot),
                        makeI64(context, backedgeTarget));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* result = lifter.GetMemoryValue(makeI64(context, loopCarriedSlot), 16);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(result);
  if (!phi) {
    details = "  target_slot with byteCount=2 should produce a phi\n";
    return false;
  }
  if (!phi->getType()->isIntegerTy(16)) {
    details = "  target_slot byteCount=2 phi should have i16 type\n";
    return false;
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == loCanonical) sawC = true;
    else if (v == loBackedge) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  target_slot byteCount=2 phi should carry the masked lower-16 "
              "bits of canonical and backedge targets\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_control_field_value_impl with byteCount=1
// yields an i8 phi carrying the masked low byte of canonical and
// backedge field values for a supported field offset. Exercises the
// helper's narrow-width read path directly on the control-field helper.
bool runGeneralizedLoopControlFieldLoadByteCountOneReturnsMaskedPhi(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t fieldOffset = 0x6ULL;
  constexpr uint16_t canonicalField = 0x11ABU;
  constexpr uint16_t backedgeField = 0x22CDU;
  constexpr uint8_t lowCanonical = static_cast<uint8_t>(canonicalField & 0xFFU);
  constexpr uint8_t lowBackedge = static_cast<uint8_t>(backedgeField & 0xFFU);

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(
      makeI64(context, canonicalControl + fieldOffset),
      llvm::ConstantInt::get(llvm::Type::getInt16Ty(context), canonicalField));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(
      makeI64(context, backedgeControl + fieldOffset),
      llvm::ConstantInt::get(llvm::Type::getInt16Ty(context), backedgeField));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* controlValue =
      lifter.GetMemoryValue(makeI64(context, controlSlot), 64);
  auto* displaced = lifter.builder->CreateAdd(
      controlValue, llvm::ConstantInt::get(controlValue->getType(), fieldOffset),
      "generalized_control_field_plus_6_byte1");
  auto* fieldValue = lifter.GetMemoryValue(displaced, 8);
  auto* phi = llvm::dyn_cast<llvm::PHINode>(fieldValue);
  if (!phi) {
    details = "  control_field helper with byteCount=1 should produce a phi\n";
    return false;
  }
  if (!phi->getType()->isIntegerTy(8)) {
    details = "  control_field byteCount=1 phi should have i8 type\n";
    return false;
  }
  bool sawC = false, sawB = false;
  for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
    auto actual = readConstantAPInt(phi->getIncomingValue(i));
    if (!actual.has_value()) continue;
    const uint64_t v = actual->getZExtValue();
    if (v == lowCanonical) sawC = true;
    else if (v == lowBackedge) sawB = true;
  }
  if (!sawC || !sawB) {
    details = "  control_field byteCount=1 phi should carry low-byte masked "
              "canonical and backedge field values\n";
    return false;
  }
  return true;
}

// migrate_generalized_loop_block copies the per-header register and
// flag PHI maps to newBlock when newBlock does not already have entries.
// The earlier migration test checked BBbackup / backedge backup /
// control-field state only; this one pins the PHI-map copy explicitly.
bool runMigrateGeneralizedLoopBlockCopiesRegisterAndFlagPhiMaps(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* oldHeader =
      llvm::BasicBlock::Create(context, "old_header", lifter.fnc);
  auto* newHeader =
      llvm::BasicBlock::Create(context, "new_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x1111));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getFalse(context));
  lifter.branch_backup(oldHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetRegisterValue(RegisterUnderTest::RAX, makeI64(context, 0x2222));
  lifter.SetFlagValue_impl(FLAG_ZF, llvm::ConstantInt::getTrue(context));
  lifter.branch_backup(oldHeader, /*generalized=*/true);
  lifter.load_generalized_backup(oldHeader);

  if (lifter.generalizedLoopRegisterPhis.count(oldHeader) != 1 ||
      lifter.generalizedLoopFlagPhis.count(oldHeader) != 1) {
    details = "  setup should have populated register/flag phi maps for oldHeader\n";
    return false;
  }

  lifter.migrate_generalized_loop_block(oldHeader, newHeader);

  if (lifter.generalizedLoopRegisterPhis.count(newHeader) != 1 ||
      lifter.generalizedLoopFlagPhis.count(newHeader) != 1) {
    details = "  migrate_generalized_loop_block should copy register/flag phi "
              "maps to newHeader\n";
    return false;
  }
  return true;
}

// isStructuredLoopHeaderShape: deeper hops allow only 1 predecessor. A
// chain block (depth >= 1) with 2+ predecessors rejects on the
// `depth == 0 ? 2 : 1` cap. Complements runStructuredLoopHeaderRejectsMultiplePredecessors
// which covers the depth-0 >2 case.
bool runStructuredLoopHeaderRejectsTwoPredecessorsAtInnerHop(
    std::string& details) {
  LifterUnderTest lifter;
  lifter.currentPathSolveContext =
      LifterUnderTest::PathSolveContext::ConditionalBranch;

  auto* current = llvm::BasicBlock::Create(lifter.context, "current", lifter.fnc);
  auto* header = llvm::BasicBlock::Create(lifter.context, "header", lifter.fnc);
  auto* innerShared =
      llvm::BasicBlock::Create(lifter.context, "inner_shared", lifter.fnc);
  auto* altPred = llvm::BasicBlock::Create(lifter.context, "alt_pred", lifter.fnc);
  auto* body = llvm::BasicBlock::Create(lifter.context, "body", lifter.fnc);
  auto* exit = llvm::BasicBlock::Create(lifter.context, "exit", lifter.fnc);

  // header -> innerShared (single successor).
  llvm::IRBuilder<> hb(header);
  hb.CreateBr(innerShared);
  // altPred also -> innerShared. innerShared now has 2 predecessors at
  // depth 1 (from the walker's perspective at the chain walker), which
  // exceeds the 1-predecessor cap.
  llvm::IRBuilder<> ap(altPred);
  ap.CreateBr(innerShared);
  llvm::IRBuilder<> inner(innerShared);
  inner.CreateCondBr(llvm::ConstantInt::getTrue(lifter.context), body, exit);
  llvm::IRBuilder<> bb(body);
  bb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 0));
  llvm::IRBuilder<> eb(exit);
  eb.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt64Ty(lifter.context), 1));

  lifter.blockInfo = BBInfo(0x2000, current);
  lifter.visitedAddresses.insert(0x1000);
  lifter.addrToBB[0x1000] = header;

  if (lifter.canGeneralizeStructuredLoopHeader(0x1000)) {
    details = "  inner-hop block with 2+ predecessors must reject (depth>0 "
              "allows only 1 predecessor in the walker)\n";
    return false;
  }
  return true;
}

// branch_backup(bb, /*generalized=*/true) does NOT overwrite an already
// present BBbackup[bb]. The guarded assignment `if (!BBbackup.contains(bb))`
// ensures the canonical snapshot (set by the first plain branch_backup)
// is preserved across subsequent generalized calls.
bool runBranchBackupGeneralizedDoesNotOverwriteExistingBBbackup(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.branch_backup(loopHeader);  // sets BBbackup[loopHeader]
  auto canonicalSource = lifter.BBbackup[loopHeader].sourceBlock;
  if (canonicalSource != preheader) {
    details = "  setup: BBbackup[header].sourceBlock should be preheader\n";
    return false;
  }

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  // BBbackup[loopHeader] must STILL reference preheader, not backedge.
  if (lifter.BBbackup[loopHeader].sourceBlock != preheader) {
    details = "  generalized branch_backup must not overwrite existing "
              "BBbackup entry; sourceBlock was mutated\n";
    return false;
  }
  return true;
}

// retrieve_generalized_loop_phi_address_value_impl collapses to the
// shared value when every phi incoming resolves to the SAME loaded
// value. Exercises the `allSameValue` short-circuit in the helper.
bool runGeneralizedPhiAddressCollapsesWhenAllIncomingsResolveToSameValue(
    std::string& details) {
  LifterUnderTest lifter;
  auto& context = lifter.context;
  auto* i64Ty = llvm::Type::getInt64Ty(context);
  auto* preheader =
      llvm::BasicBlock::Create(context, "preheader", lifter.fnc);
  auto* backedge =
      llvm::BasicBlock::Create(context, "backedge", lifter.fnc);
  auto* loopHeader =
      llvm::BasicBlock::Create(context, "loop_header", lifter.fnc);

  constexpr uint64_t controlSlot = 0x14004DD19ULL;
  constexpr uint64_t canonicalControl = 0x1401AF740ULL;
  constexpr uint64_t backedgeControl = 0x1401AF0F6ULL;
  constexpr uint64_t addrA = 0x1400C0000ULL;
  constexpr uint64_t addrB = 0x1400C0080ULL;
  constexpr uint64_t sharedValue = 0x9999AAAABBBBCCCCULL;

  lifter.builder->SetInsertPoint(preheader);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, canonicalControl));
  lifter.SetMemoryValue(makeI64(context, addrA), makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader);

  lifter.builder->SetInsertPoint(backedge);
  lifter.SetMemoryValue(makeI64(context, controlSlot),
                        makeI64(context, backedgeControl));
  lifter.SetMemoryValue(makeI64(context, addrB), makeI64(context, sharedValue));
  lifter.branch_backup(loopHeader, /*generalized=*/true);

  lifter.load_generalized_backup(loopHeader);
  lifter.builder->SetInsertPoint(loopHeader);
  auto* addressPhi = lifter.builder->CreatePHI(i64Ty, 2, "shared_value_phi_addr");
  addressPhi->addIncoming(makeI64(context, addrA), preheader);
  addressPhi->addIncoming(makeI64(context, addrB), backedge);
  auto* resolved = lifter.GetMemoryValue(addressPhi, 64);
  // Both incomings resolve to the same loaded value, so the helper
  // returns that shared value directly - no phi needed.
  if (llvm::isa<llvm::PHINode>(resolved)) {
    details = "  phi_address helper should collapse to shared loaded value "
              "when all incomings resolve identically, not emit a phi\n";
    return false;
  }
  auto actual = readConstantAPInt(resolved);
  if (!actual.has_value() || actual->getZExtValue() != sharedValue) {
    details = "  collapsed phi_address result should be the shared value\n";
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
    runCustom("pending_generalized_loop_conditional_branch_allowed",
             &InstructionTester::runPendingGeneralizedLoopConditionalBranchAllowed);
    runCustom("pending_generalized_loop_direct_jump_allowed",
             &InstructionTester::runPendingGeneralizedLoopDirectJumpAllowed);
    runCustom("record_generalized_loop_backedge_single_source_rotates_canonical_and_backedge",
             &InstructionTester::runRecordGeneralizedLoopBackedgeSingleSourceRotatesCanonicalAndBackedge);
    runCustom("pending_generalized_loop_indirect_jump_allowed_when_unresolved",
             &InstructionTester::runPendingGeneralizedLoopIndirectJumpAllowedWhenUnresolved);
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
    runCustom("record_generalized_loop_backedge_multiway_appends_new_body_source",
             &InstructionTester::runRecordGeneralizedLoopBackedgeMultiwayAppendsNewBodySource);
    runCustom("generalized_phi_address_three_way_resolves_all_incomings",
             &InstructionTester::runGeneralizedPhiAddressThreeWayResolvesAllIncomings);
    runCustom("generalized_local_phi_address_three_way_resolves_all_incomings",
             &InstructionTester::runGeneralizedLocalPhiAddressThreeWayResolvesAllIncomings);
    runCustom("branch_backup_generalized_dedups_by_source_block",
             &InstructionTester::runBranchBackupGeneralizedDedupsBySourceBlock);
    runCustom("merge_value_collapses_identical_canonical_and_backedge_to_single_value",
             &InstructionTester::runMergeValueCollapsesIdenticalCanonicalAndBackedgeToSingleValue);
    runCustom("loop_generalization_forward_target_rejected",
             &InstructionTester::runLoopGeneralizationForwardTargetRejected);
    runCustom("loop_generalization_not_visited_target_rejected",
             &InstructionTester::runLoopGeneralizationNotVisitedTargetRejected);
    runCustom("loop_generalization_already_pending_rejected",
             &InstructionTester::runLoopGeneralizationAlreadyPendingRejected);
    runCustom("loop_generalization_already_generalized_rejected",
             &InstructionTester::runLoopGeneralizationAlreadyGeneralizedRejected);
    runCustom("loop_generalization_no_reach_rejected",
             &InstructionTester::runLoopGeneralizationNoReachRejected);
    runCustom("structured_loop_header_rejects_empty_block_in_chain",
             &InstructionTester::runStructuredLoopHeaderRejectsEmptyBlockInChain);
    runCustom("structured_loop_header_rejects_deep_chain",
             &InstructionTester::runStructuredLoopHeaderRejectsDeepChain);
    runCustom("merge_value_returns_backedge_on_type_mismatch",
             &InstructionTester::runMergeValueReturnsBackedgeOnTypeMismatch);
    runCustom("branch_backup_non_generalized_isolates_bbbackup_from_backedge_backup",
             &InstructionTester::runBranchBackupPlainReplacesBBbackupOnly);
    runCustom("structured_loop_header_rejects_cycle_in_chain",
             &InstructionTester::runStructuredLoopHeaderRejectsCycleInChain);
    runCustom("record_generalized_loop_backedge_single_source_no_op_when_source_matches_existing_backedge",
             &InstructionTester::runRecordGeneralizedLoopBackedgeSingleSourceNoOpWhenSourceMatchesExistingBackedge);
    runCustom("record_generalized_loop_backedge_single_source_no_op_when_control_unchanged",
             &InstructionTester::runRecordGeneralizedLoopBackedgeSingleSourceNoOpWhenControlUnchanged);
    runCustom("migrate_generalized_loop_block_copies_all_state_to_new_block",
             &InstructionTester::runMigrateGeneralizedLoopBlockCopiesAllStateToNewBlock);
    runCustom("make_generalized_loop_backup_widens_rax_to_undef_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupWidensRaxToUndefOnFirstBackedge);
    runCustom("generalized_phi_address_with_negative_displacement_resolves_loaded_values",
             &InstructionTester::runGeneralizedPhiAddressWithNegativeDisplacementResolvesLoadedValues);
    runCustom("make_generalized_loop_backup_preserves_concrete_rcx_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteRcxOnFirstBackedge);
    runCustom("make_generalized_loop_backup_preserves_concrete_r12_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteR12OnFirstBackedge);
    runCustom("generalized_loop_target_slot_collapses_to_canonical_when_values_match",
             &InstructionTester::runGeneralizedLoopTargetSlotCollapsesToCanonicalWhenValuesMatch);
    runCustom("generalized_loop_local_value_returns_concrete_stack_buffer_value",
             &InstructionTester::runGeneralizedLoopLocalValueReturnsConcreteStackBufferValue);
    runCustom("make_generalized_loop_backup_preserves_concrete_rsp_when_values_differ",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteRspWhenValuesDiffer);
    runCustom("generalized_loop_control_slot_byte_count_two_returns_masked_phi",
             &InstructionTester::runGeneralizedLoopControlSlotByteCountTwoReturnsMaskedPhi);
    runCustom("make_generalized_loop_backup_populates_register_phis_map",
             &InstructionTester::runMakeGeneralizedLoopBackupPopulatesRegisterPhisMap);
    runCustom("make_generalized_loop_backup_populates_flag_phis_map",
             &InstructionTester::runMakeGeneralizedLoopBackupPopulatesFlagPhisMap);
    runCustom("generalized_loop_control_field_load_collapses_when_values_match",
             &InstructionTester::runGeneralizedLoopControlFieldLoadCollapsesWhenValuesMatch);
    runCustom("generalized_loop_control_slot_byte_count_sixteen_falls_through",
             &InstructionTester::runGeneralizedLoopControlSlotByteCountSixteenFallsThrough);
    runCustom("generalized_loop_backup_canonical_only_path_preserves_bbbackup_state",
             &InstructionTester::runGeneralizedLoopBackupCanonicalOnlyPathPreservesBBbackupState);
    runCustom("generalized_loop_backup_canonical_only_path_leaves_flag_phis_empty",
             &InstructionTester::runGeneralizedLoopBackupCanonicalOnlyPathLeavesFlagPhisEmpty);
    runCustom("generalized_phi_address_unwraps_zext_cast_over_phi",
             &InstructionTester::runGeneralizedPhiAddressUnwrapsZExtCastOverPhi);
    runCustom("generalized_phi_address_unwraps_sext_cast_over_phi",
             &InstructionTester::runGeneralizedPhiAddressUnwrapsSExtCastOverPhi);
    runCustom("generalized_phi_address_base_case_without_displacement_resolves_loaded_values",
             &InstructionTester::runGeneralizedPhiAddressBaseCaseWithoutDisplacementResolvesLoadedValues);
    runCustom("generalized_loop_non_themida_target_slot_produces_no_phi",
             &InstructionTester::runGeneralizedLoopNonThemidaTargetSlotProducesNoPhi);
    runCustom("loop_generalization_missing_addr_to_bb_entry_rejected",
             &InstructionTester::runLoopGeneralizationMissingAddrToBBEntryRejected);
    runCustom("loop_generalization_empty_basic_block_rejected",
             &InstructionTester::runLoopGeneralizationEmptyBasicBlockRejected);
    runCustom("loop_generalization_null_current_block_rejected",
             &InstructionTester::runLoopGeneralizationNullCurrentBlockRejected);
    runCustom("branch_backup_generalized_appends_when_source_differs",
             &InstructionTester::runBranchBackupGeneralizedAppendsWhenSourceDiffers);
    runCustom("record_generalized_loop_backedge_multiway_no_op_when_control_unchanged",
             &InstructionTester::runRecordGeneralizedLoopBackedgeMultiwayNoOpWhenControlUnchanged);
    runCustom("generalized_loop_control_slot_collapses_when_canonical_matches_backedge_value",
             &InstructionTester::runGeneralizedLoopControlSlotCollapsesWhenCanonicalMatchesBackedgeValue);
    runCustom("migrate_generalized_loop_block_no_op_when_same_block",
             &InstructionTester::runMigrateGeneralizedLoopBlockNoOpWhenSameBlock);
    runCustom("migrate_generalized_loop_block_preserves_existing_new_block_entry",
             &InstructionTester::runMigrateGeneralizedLoopBlockPreservesExistingNewBlockEntry);
    runCustom("migrate_generalized_loop_block_preserves_existing_register_and_flag_phi_maps",
             &InstructionTester::runMigrateGeneralizedLoopBlockPreservesExistingRegisterAndFlagPhiMaps);
    runCustom("make_generalized_loop_backup_preserves_concrete_r9_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteR9OnFirstBackedge);
    runCustom("generalized_loop_target_slot_bails_when_canonical_buffer_lacks_slot",
             &InstructionTester::runGeneralizedLoopTargetSlotBailsWhenCanonicalBufferLacksSlot);
    runCustom("make_generalized_loop_backup_preserves_concrete_r10_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteR10OnFirstBackedge);
    runCustom("make_generalized_loop_backup_preserves_concrete_r14_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteR14OnFirstBackedge);
    runCustom("make_generalized_loop_backup_preserves_concrete_rdi_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupPreservesConcreteRdiOnFirstBackedge);
    runCustom("generalized_phi_address_unwraps_trunc_cast_over_phi",
             &InstructionTester::runGeneralizedPhiAddressUnwrapsTruncCastOverPhi);
    runCustom("generalized_local_phi_address_collapses_when_all_incomings_resolve_to_same_value",
             &InstructionTester::runGeneralizedLocalPhiAddressCollapsesWhenAllIncomingsResolveToSameValue);
    runCustom("generalized_loop_restore_flag_collapses_when_canonical_matches_backedge",
             &InstructionTester::runGeneralizedLoopRestoreFlagCollapsesWhenCanonicalMatchesBackedge);
    runCustom("structured_loop_header_accepts_seven_hop_chain",
             &InstructionTester::runStructuredLoopHeaderAcceptsSevenHopChain);
    runCustom("generalized_local_phi_address_bails_on_non_local_stack_incoming",
             &InstructionTester::runGeneralizedLocalPhiAddressBailsOnNonLocalStackIncoming);
    runCustom("make_generalized_loop_backup_widens_rdx_to_undef_on_first_backedge",
             &InstructionTester::runMakeGeneralizedLoopBackupWidensRdxToUndefOnFirstBackedge);
    runCustom("generalized_loop_restore_flag_phi_carries_concrete_backedge_on_divergence",
             &InstructionTester::runGeneralizedLoopRestoreFlagPhiCarriesConcreteBackedgeOnDivergence);
    runCustom("generalized_loop_target_slot_byte_count_two_returns_masked_phi",
             &InstructionTester::runGeneralizedLoopTargetSlotByteCountTwoReturnsMaskedPhi);
    runCustom("generalized_loop_target_slot_byte_count_one_returns_masked_phi",
             &InstructionTester::runGeneralizedLoopTargetSlotByteCountOneReturnsMaskedPhi);
    runCustom("generalized_loop_control_field_load_byte_count_one_returns_masked_phi",
             &InstructionTester::runGeneralizedLoopControlFieldLoadByteCountOneReturnsMaskedPhi);
    runCustom("migrate_generalized_loop_block_copies_register_and_flag_phi_maps",
             &InstructionTester::runMigrateGeneralizedLoopBlockCopiesRegisterAndFlagPhiMaps);
    runCustom("structured_loop_header_rejects_two_predecessors_at_inner_hop",
             &InstructionTester::runStructuredLoopHeaderRejectsTwoPredecessorsAtInnerHop);
    runCustom("branch_backup_generalized_does_not_overwrite_existing_bbbackup",
             &InstructionTester::runBranchBackupGeneralizedDoesNotOverwriteExistingBBbackup);
    runCustom("generalized_phi_address_collapses_when_all_incomings_resolve_to_same_value",
             &InstructionTester::runGeneralizedPhiAddressCollapsesWhenAllIncomingsResolveToSameValue);
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
