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
