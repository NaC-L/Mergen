
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
    ZydisRegister reg;
    uint64_t value;
  };

  struct FlagsState {
    Flag flag;
    FlagState state;
  };

  std::string name;

  // Inputs
  std::vector<uint8_t> instruction_bytes;
  std::vector<RegisterState> initial_registers;
  std::vector<FlagsState> initial_flags;

  // Expected outputs
  std::vector<RegisterState> expected_registers;
  std::vector<FlagsState> expected_flags;
};

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
      if (!isRegisterEqualTo(expected.reg, expected.value, false)) {

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

    for (const auto& flag : tc.expected_flags) {
      FlagState flagState = getFlagState(flag.flag);
      if (flagState != flag.state) {
        failureDetails << "Incorrect flag:" //
                       << "\n Flag: " << flag.flag
                       << "\n Expected: " << flag.state
                       << "\n Actual: " << flagState;

        isSuccessfull = false;
      }
    }

    // TODO: check for unexpected changes

    std::cout << "[" << (isSuccessfull ? "  OK  " : " FAIL ") << "] " << tc.name
              << "\n";
    if (!isSuccessfull)
      std::cout << failureDetails.str() << std::endl;

    return isSuccessfull;
  }

  int runAllTests() {
    int failures = 0;
    for (const auto& [testFn, name] : tests) {
      reset();
      bool result = testFn(this);
      std::cout << "[" << (result ? "  OK  " : " FAIL ") << "] " << name
                << "\n";
      failures += result;
    }

    for (const auto& tc : testCases) {
      reset();
      failures += execute_test_case(tc);
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
    auto val = lifter->GetRegisterValue(reg);

    if (auto a_c = dyn_cast<ConstantInt>(val)) {
      return (a_c->equalsInt(v));
    }

    if (couldBeUndefined && isa<UndefValue>(val))
      return 1;

    return 0;
  }

  void setRegister(ZydisRegister reg, uint64_t value) {
    lifter->SetRegisterValue(reg, lifter->builder.getInt64(value));
  }

  Value* getRegister(ZydisRegister reg) {
    auto val = lifter->GetRegisterValue(reg);
    return val;
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

    ZydisDecoderDecodeFull(&decoder, bytes.data(), 15, &(lifter->instruction),
                           lifter->operands);

    lifter->liftInstructionSemantics();
  }
};
