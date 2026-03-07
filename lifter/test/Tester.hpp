#pragma once

#include "LifterClass_Concolic.hpp"
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/IR/Constants.h>
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

      auto expectedValue = expected.value.zextOrTrunc(actual->getBitWidth());
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
