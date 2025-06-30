#pragma once

#include "CommonRegisters.h"
#include "utils.h"
#include <array>
#include <assert.h>
#include <concepts>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <vector>

enum Flag {
  FLAG_CF = 0,        // Carry flag
  FLAG_RESERVED1 = 1, // Reserved, typically not
                      // used by programs
  FLAG_PF = 2,        // Parity flag
  FLAG_RESERVED3 = 3, // Reserved, typically not
                      // used by programs
  FLAG_AF = 4,        // Auxiliary Carry flag
  FLAG_RESERVED5 = 5, // Reserved, typically not
                      // used by programs
  FLAG_ZF = 6,        // Zero flag
  FLAG_SF = 7,        // Sign flag
  FLAG_TF = 8,        // Trap flag
  FLAG_IF = 9,        // Interrupt enable flag
  FLAG_DF = 10,       // Direction flag
  FLAG_OF = 11,       // Overflow flag
  FLAG_IOPL = 12,     // I/O privilege level (286+ only)
                      // always all-1s on 8086 and 186
  FLAG_IOPL2 = 13,    // I/O privilege level (286+ only)
                      // always all-1s on 8086 and 186
  FLAG_NT = 14,       // Nested task flag (286+ only),
                      // always 1 on 8086 and 186
  FLAG_MD = 15,       // Mode flag (NEC V-series only),
                      // reserved on all Intel CPUs. Always 1
                      // on 8086 / 186, 0 on 286 and later.
  FLAG_RF = 16,       // Resume flag (386+ only)
  FLAG_VM = 17,       // Virtual 8086 mode flag (386+ only)
  FLAG_AC = 18,       // Alignment Check (486+, ring 3),
  FLAG_VIF = 19,      // Virtual interrupt flag (Pentium+)
  FLAG_VIP = 20,      // Virtual interrupt pending (Pentium+)
  FLAG_ID = 21,       // Able to use CPUID instruction
                      // (Pentium+)
  FLAG_RES22 = 22,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES23 = 23,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES24 = 24,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES25 = 25,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES26 = 26,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES27 = 27,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES28 = 28,    //  Reserved, typically not
                      //  used by programs
  FLAG_RES29 = 29,    //  Reserved, typically not
                      //  used by programs
  FLAG_AES = 30,      // AES key schedule loaded flag
  FLAG_AI = 31,       // Alternate Instruction Set enabled
  // reserved above 32-63
  FLAGS_START = FLAG_CF,
  FLAGS_END = FLAG_IOPL
};

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

template <typename T, typename reg>
concept RegisterManagerConcept = Registers<reg> && requires(T t, reg key) {
  { t.get_impl(std::declval<reg>()) } -> std::same_as<llvm::Value*>;
  {
    t.set_impl(std::declval<reg>(), std::declval<llvm::Value*>())
  } -> std::same_as<void>;
  {
    t.init_impl(std::declval<std::vector<std::pair<reg, llvm::Value*>>>())
  } -> std::same_as<void>;

  { t.get_flag_impl(std::declval<Flag>()) } -> std::same_as<llvm::Value*>;
  {
    t.set_flag_impl(std::declval<Flag>(), std::declval<llvm::Value*>())
  } -> std::same_as<void>;
  {
    t.init_flag_impl(std::declval<std::vector<std::pair<Flag, llvm::Value*>>>())
  } -> std::same_as<void>;
};

template <typename Derived, Registers Register> class RegisterManagerBase {
public:
  RegisterManagerBase() {
    static_assert(RegisterManagerConcept<Derived, Register>,
                  "Derived should satisfy RegisterManagerConcept");
  }
  llvm::Value* get(Register key) {
    return static_cast<Derived*>(this)->get_impl(key);
  }

  void set(Register key, llvm::Value* value) {
    static_cast<Derived*>(this)->set_impl(key, value);
  }

  void init(std::vector<std::pair<Register, llvm::Value*>> values) {
    static_cast<Derived*>(this)->init_impl(values);
  }

  llvm::Value* get(Flag key) {
    return static_cast<Derived*>(this)->get_flag_impl(key);
  }

  void set(Flag key, llvm::Value* value) {
    static_cast<Derived*>(this)->set_flag_impl(key, value);
  }

  void init_flag(std::vector<std::pair<Flag, llvm::Value*>> values) {
    static_cast<Derived*>(this)->init_flag_impl(values);
  }
};

template <Registers Register>
class RegisterManagerConcolic
    : public RegisterManagerBase<RegisterManagerConcolic<Register>, Register> {
public:
  enum RegisterIndex {
    RAX_ = 0,
    RCX_ = 1,
    RDX_ = 2,
    RBX_ = 3,
    RSP_ = 4,
    RBP_ = 5,
    RSI_ = 6,
    RDI_ = 7,
    R8_ = 8,
    R9_ = 9,
    R10_ = 10,
    R11_ = 11,
    R12_ = 12,
    R13_ = 13,
    R14_ = 14,
    R15_ = 15,
    RIP_ = 16,
    RFLAGS_ = 17,
    REGISTER_COUNT = RFLAGS_ // Total number of registers
  };
  std::array<llvm::Value*, REGISTER_COUNT> vec;
  std::array<llvm::Value*, FLAGS_END> vecflag;

  // llvm::IRBuilder<>& irb;
  // RegisterManagerConcolic(llvm::IRBuilder<>& builder) : irb(builder) {}

  RegisterManagerConcolic() {}
  RegisterManagerConcolic(RegisterManagerConcolic& other)
      : vec(other.vec), vecflag(other.vecflag) {}
  RegisterManagerConcolic(RegisterManagerConcolic&& other)
      : vec(other.vec), vecflag(other.vecflag) {}
  RegisterManagerConcolic(const RegisterManagerConcolic& other)
      : vec(other.vec), vecflag(other.vecflag) {}
  RegisterManagerConcolic(const RegisterManagerConcolic&& other)
      : vec(other.vec), vecflag(other.vecflag) {}

  RegisterManagerConcolic& operator=(const RegisterManagerConcolic& other) {
    vec = other.vec;
    vecflag = other.vecflag;
    return *this;
  };

  // Overload the [] operator for getting register values

  int getRegisterIndex(Register key) const {

    switch (key) {
    case Register::RIP: {
      return RIP_;
    }
    case Register::RFLAGS: {
      return RFLAGS_;
    }
    default: {
      assert(((key >= Register::RAX && key <= Register::R15) ||
              key == Register::EIP || key == Register::RIP) &&
             "Key must be between RAX and R15");

      return (static_cast<int>(key) - static_cast<int>(Register::RAX));
    }
    }
  }

  llvm::Value* get_impl(Register key) {
    int index = getRegisterIndex(key);
    printvalue2(index);
    return vec[index];
  }

  void set_impl(Register key, llvm::Value* val) {
    int index = getRegisterIndex(key);
    vec[index] = val;
  }

  void init_impl(std::vector<std::pair<Register, llvm::Value*>> values) {
    for (auto& [reg, val] : values) {
      int index = getRegisterIndex(reg);
      vec[index] = val;
    }
  }

  llvm::Value* get_flag_impl(Flag key) {
    return vecflag[static_cast<uint8_t>(key)];
  }

  void set_flag_impl(Flag key, llvm::Value* val) {
    vecflag[static_cast<uint8_t>(key)] = val;
  }
  void init_flag_impl(std::vector<std::pair<Flag, llvm::Value*>> values) {
    for (auto& [reg, val] : values) {
      vec[static_cast<uint8_t>(reg)] = val;
    }
  }
};
/*
template <Registers Register>
class RegisterManagerStatic
    : public RegisterManagerBase<RegisterManagerStatic<Register>, Register> {
public:
  // llvm::Value* get_impl(Register key) {
  //
  //}

  // void set_impl(Register key, llvm::Value* val) {}
};
 */