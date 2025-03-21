#pragma once

#include "ZydisDisassembler.hpp"
#include "includes.h"
#include "lifterClass.h"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Disassembler.h>
#include <Zydis/Register.h>
#include <llvm/IR/Constants.h>

#include <iostream>
#include <llvm/Support/raw_ostream.h>

enum FlagState { UNDEF = -1, CLEAR = 0, SET = 1, UNKNOWN };

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& os,
                                     const FlagState state) {
  switch (state) {
  case UNDEF:
    os << "UNDEF";
    break;
  case CLEAR:
    os << "CLEAR";
    break;
  case SET:
    os << "SET";
    break;
  case UNKNOWN:
    os << "UNKNOWN";
    break;
  }
  return os;
}

struct TestCase {

  struct RegisterState {
    ZydisRegister reg = ZYDIS_REGISTER_NONE;
    uint64_t value;
  };

  struct FlagsStatus {
    Flag flag = FLAGS_END;
    FlagState state = UNKNOWN; // to catch bugs
  };

  std::string name;

  // Inputs
  // TODO: std::array for constexpr
  std::vector<uint8_t> instruction_bytes;
  std::vector<RegisterState> initial_registers;
  std::vector<FlagsStatus> initial_flags;

  // Expected outputs
  std::vector<RegisterState> expected_registers;
  std::vector<FlagsStatus> expected_flags;
  bool couldBeUndefined = true;
};

inline std::vector<TestCase::FlagsStatus> parseFlagStates(uint64_t flagint) {
  std::vector<TestCase::FlagsStatus> result;
  result.resize(FLAGS_END);

  for (size_t i = 0; i < FLAGS_END; i++) {
    bool isSet = (flagint >> i) & 1;
    result[i] = TestCase::FlagsStatus{
        .flag = (Flag)i, .state = isSet ? FlagState::SET : FlagState::CLEAR};
  }

  return result;
}

class Tester {
public:
  ZydisDecoder decoder;
  lifterClass* lifter;

  using TestFunction = std::function<bool(Tester*)>;

  std::vector<std::pair<TestFunction, std::string>> tests;
  std::vector<TestCase> testCases;

  void addTest(TestFunction fn, const std::string& name) {
    tests.emplace_back(fn, name);
  }
  void addTest(const TestCase& fn) {
    //
    testCases.emplace_back(fn);
  }

  bool execute_test_case(const TestCase& tc) {

    bool isSuccessfull = true;
    std::string str;
    llvm::raw_string_ostream failureDetails(str);

    for (const auto& reg : tc.initial_registers) {
      setRegister(reg.reg, reg.value);
    }

    for (const auto& reg : tc.initial_flags) {
      setFlag(reg.flag, reg.state);
    }

    disassembleBytesAndLift(tc.instruction_bytes);

    // Verify registers
    for (const auto& expected : tc.expected_registers) {
      // registers usually shouldn't be undefined
      if (!isRegisterEqualTo(expected.reg, expected.value,
                             tc.couldBeUndefined)) {

        failureDetails << "Incorrect register:" << "\n Register: "
                       << ZydisRegisterGetString(expected.reg)
                       << "\n Expected: " << expected.value
                       << "\n Actual: " /*                      */;

        // print register

        // print as const if possible for convenience
        getRegister(expected.reg)->print(failureDetails);

        failureDetails << "\n";

        isSuccessfull = false;
      }
    }

    const auto flagcompare = [](FlagState original, FlagState compare,
                                bool couldBeUndefined = true) {
      if (couldBeUndefined && original == FlagState::UNDEF)
        return true;
      return original == compare;
    };

    for (const auto& flag : tc.expected_flags) {
      FlagState flagState = getFlagState(flag.flag);
      if (!flagcompare(flagState, flag.state, tc.couldBeUndefined)) {

        failureDetails << "Incorrect flag:" //
                       << "\n Flag: " << flag.flag << "(" << (int)flag.flag
                       << ")" << "\n Expected: " << flag.state
                       << "\n Actual: " << flagState << "\n";

        isSuccessfull = false;
      }
    }

    // TODO: check for unexpected changes

    std::cout << "[" << (isSuccessfull ? "  OK  " : " FAIL ") << "] " << tc.name
              << "\n";
    if (!isSuccessfull) {
      std::cout << failureDetails.str() << std::endl;
    }

    return isSuccessfull;
  }

  int runAllTests() {
    int failures = 0;
    for (const auto& [testFn, name] : tests) {
      reset();
      bool result = testFn(this);
      std::cout << "[" << (result ? "  OK  " : " FAIL ") << "] " << name
                << "\n";
      failures += !result;
      if (!result)
        exit(0);
    }

    for (const auto& tc : testCases) {
      reset();
      bool result = execute_test_case(tc);
      failures += !result;
      if (!result)
        exit(0);
    }

    return failures;
  }

  Tester(lifterClass* lifter, bool is64Bit = true) : lifter(lifter) {

    ZydisDecoderInit(&decoder,
                     is64Bit ? ZYDIS_MACHINE_MODE_LONG_64
                             : ZYDIS_MACHINE_MODE_LEGACY_32,
                     is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    reset();
  }

  bool isRegisterEqualTo(ZydisRegister reg, uint64_t v,
                         bool couldBeUndefined = true) {
    /*
    auto val = lifter->GetRegisterValue(zydisRegisterToMergenRegister(reg));

    if (auto a_c = dyn_cast<ConstantInt>(val)) {
      return (a_c->equalsInt(v));
    }

    if (couldBeUndefined && isa<UndefValue>(val))
      return 1;
    */

    return 0;
  }

  void setRegister(ZydisRegister reg, uint64_t value) {
    // lifter->SetRegisterValue(zydisRegisterToMergenRegister(reg),
    //                           lifter->builder.getInt64(value));
  }

  Value* getRegister(ZydisRegister reg) {
    // auto val = lifter->GetRegisterValue(zydisRegisterToMergenRegister(reg));
    return nullptr;
  }

  Value* getFlag(Flag reg) {
    //
    return lifter->getFlag(reg);
  }

  FlagState getFlagState(Flag reg) {
    auto flag = lifter->getFlag(reg);
    if (isa<UndefValue>(flag))
      return FlagState::UNDEF;
    if (auto flagv = dyn_cast<ConstantInt>(flag)) {
      if (flagv->getZExtValue() == 0)
        return FlagState::CLEAR;
      if (flagv->getZExtValue() == 1)
        return FlagState::SET;
    }
    return FlagState::UNKNOWN;
  }

  void setFlagState(Flag flag, FlagState state) {
    switch (state) {
    case FlagState::CLEAR:
    case FlagState::SET: {
      lifter->setFlag(flag, lifter->builder.getInt1(state));
      break;
    }
    case FlagState::UNDEF: {

      auto undef_f = UndefValue::get(lifter->builder.getInt1Ty());
      lifter->setFlag(flag, undef_f);
      break;
    }
    case FlagState::UNKNOWN: {
      // ?
      break;
    }
    }
  }

  void setFlag(Flag reg, uint64_t value) {
    lifter->setFlag(reg, lifter->builder.getInt64(value));
  }

  void resetRegistersAndFlags() {
    //
    // set every value to undef
    auto undef = UndefValue::get(lifter->builder.getInt64Ty());
    auto undef_f = UndefValue::get(lifter->builder.getInt1Ty());
    for (int i = 0; i < RegisterManager::RegisterIndex::REGISTER_COUNT; i++)
      lifter->Registers.vec[i] = undef;

    for (int i = 0; i < FLAGS_END; i++)
      lifter->FlagList[i] = undef;
  }

  void reset() {
    //
    resetRegistersAndFlags();
  }

  void disassembleBytesAndLift(const std::vector<uint8_t>& bytes) {
    ZydisDecodedInstruction instruction;
    ZydisDecoderDecodeFull(&decoder, bytes.data(), 15, &instruction,
                           lifter->operands);

    lifter->instruction.attributes = instruction.attributes;

    lifter->instruction.mnemonic = (Mnemonic)(instruction.mnemonic - 1);

    // lifter->instruction.operand_count_total = instruction.operand_count;

    lifter->instruction.operand_count_visible =
        instruction.operand_count_visible;

    lifter->liftInstructionSemantics();
  }
};
