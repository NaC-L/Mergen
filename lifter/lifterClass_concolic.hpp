#ifndef LIFTERCLASS_CONCRETE_H
#define LIFTERCLASS_CONCRETE_H
#include "CommonDisassembler.hpp"
#include "icedDisassembler.hpp"
#include "icedDisassembler_mnemonics.h"
#include "icedDisassembler_registers.h"
#include "lifterClass.hpp"
#include <magic_enum/magic_enum.hpp>

template <
#ifdef ICED_FOUND
    Registers Register = Mergen::IcedRegister,
    Mnemonics Mnemonic = Mergen::IcedMnemonics,
    template <typename, typename> class DisassemblerBase =
        Mergen::icedDisassembler
#else

    Registers Register = Mergen::ZydisRegister,
    Mnemonics Mnemonic = Mergen::ZydisMnemonic,
    template <typename, typename> class DisassemblerBase =
        Mergen::ZydisDisassembler
#endif
    >

  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>

class lifterConcolic : public lifterClassBase<
                           lifterConcolic<Register, Mnemonic, DisassemblerBase>,
                           Mnemonic, Register, DisassemblerBase> {
public:
  // lifterConcolic constructor will be executed after lifterClassBase
  // https://godbolt.org/z/f986zK5j1

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

    return vec[index];
  }

  void set_impl(Register key, llvm::Value* val) {
    // printvalue2(int(key));
    // printvalue2(magic_enum::enum_name(key))
    int keyindex = getRegisterIndex(key);
    // printvalue2(keyindex);
    // printvalue(val);
    vec[keyindex] = val;
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

  llvm::Value* GetRegisterValue_impl(Register key) { return get_impl(key); }
  void SetRegisterValue_impl(Register key, llvm::Value* val) {

    set_impl(key, val);
  }

  struct backup_point {
    std::array<llvm::Value*, REGISTER_COUNT> vec;
    std::array<llvm::Value*, FLAGS_END> vecflag;
    llvm::DenseMap<uint64_t, ValueByteReference> buffer;
    InstructionCache cache;
    llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
    uint64_t ct;

    bool operator==(const backup_point& other) const {
      if (buffer != other.buffer)
        return false;
      return vec == other.vec && vecflag == other.vecflag;
    }

    backup_point(backup_point& other)
        : vec(other.vec), vecflag(other.vecflag), buffer(other.buffer),
          cache(other.cache), assumptions(other.assumptions), ct(other.ct){};

    backup_point(backup_point&& other) noexcept
        : vec(std::move(other.vec)), vecflag(std::move(other.vecflag)),
          buffer(std::move(other.buffer)), cache(std::move(other.cache)),
          assumptions(other.assumptions), ct(other.ct) {}

    backup_point(std::array<llvm::Value*, REGISTER_COUNT> vec,
                 std::array<llvm::Value*, FLAGS_END> vecflag,
                 llvm::DenseMap<uint64_t, ValueByteReference> buffer,
                 InstructionCache cc,
                 llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions,
                 uint64_t ct)
        : vec(vec), vecflag(vecflag), buffer(buffer), cache(cc),
          assumptions(assumptions), ct(ct){};
    backup_point() = default;
    backup_point(const backup_point&) = default;
    backup_point(const backup_point&&) noexcept = default;
    backup_point& operator=(const backup_point&) = default;
  };

  llvm::DenseMap<BasicBlock*, backup_point> BBbackup;
  void branch_backup_impl(BasicBlock* bb) {
    //

    printvalue2("backing up");
    printvalue2(this->counter);
    BBbackup[bb] = backup_point(vec, vecflag, this->buffer, this->cache,
                                this->assumptions, this->counter);
  }

  void load_backup_impl(BasicBlock* bb) {
    if (BBbackup.contains(bb)) {

      printvalue2("loading backup");
      backup_point bbinfo = BBbackup[bb];
      vec = bbinfo.vec;
      vecflag = bbinfo.vecflag;
      this->buffer = bbinfo.buffer;
      this->cache = bbinfo.cache;
      this->assumptions = bbinfo.assumptions;
      this->counter = bbinfo.ct;
    }
  }
};
#endif