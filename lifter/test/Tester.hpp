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
    runCustom("loop_generalization_conditional_branch_allowed",
             &InstructionTester::runLoopGeneralizationConditionalBranchAllowed);
    runCustom("loop_generalization_direct_jump_allowed",
             &InstructionTester::runLoopGeneralizationDirectJumpAllowed);
    runCustom("loop_generalization_indirect_jump_blocked_when_unresolved",
             &InstructionTester::runLoopGeneralizationIndirectJumpBlockedWhenUnresolved);
    runCustom("loop_generalization_indirect_jump_allowed_when_resolved",
             &InstructionTester::runLoopGeneralizationIndirectJumpAllowedWhenResolved);
    runCustom("loop_generalization_ret_blocked",
             &InstructionTester::runLoopGeneralizationRetBlocked);
    runCustom("pending_generalized_loop_indirect_jump_allowed_when_resolved",
             &InstructionTester::runPendingGeneralizedLoopIndirectJumpAllowedWhenResolved);
    runCustom("pending_generalized_loop_ret_blocked",
             &InstructionTester::runPendingGeneralizedLoopRetBlocked);
    runCustom("structured_loop_header_allows_conditional_backedge",
             &InstructionTester::runStructuredLoopHeaderAllowsConditionalBackedge);
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
    runCustom("generalized_loop_restore_merges_backedge_register_state",
             &InstructionTester::runGeneralizedLoopRestoreMergesBackedgeRegisterState);
    runCustom("solve_load_infers_concrete_base_from_tracked_load",
             &InstructionTester::runSolveLoadInfersConcreteBaseFromTrackedLoad);
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
