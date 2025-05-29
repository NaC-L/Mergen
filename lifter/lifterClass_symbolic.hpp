#ifndef LIFTERCLASS_SYMBOLIC_H
#define LIFTERCLASS_SYMBOLIC_H

#include "CommonDisassembler.hpp"
#include "icedDisassembler.hpp"
#include "icedDisassembler_mnemonics.h"
#include "icedDisassembler_registers.h"
#include "lifterClass.hpp"

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

class lifterSymbolic : public lifterClassBase<
                           lifterSymbolic<Register, Mnemonic, DisassemblerBase>,
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

  llvm::Value* GetRegisterValue_impl(Register key) {
    int index = getRegisterIndex(key);
    // pretty sure it will get biggest reg but whatever
    auto size = getRegisterSize(key);
    auto v =
        this->builder->CreateLoad(this->builder->getIntNTy(size), vec[index]);
    return v;
    // load value
  }

  void SetRegisterValue_impl(Register key, llvm::Value* val) {
    this->builder->CreateStore(vec[key], val);
    // store value
  }

  void branch_backup_impl(BasicBlock* bb) {
    //
    return;
  }

  void load_backup_impl(BasicBlock* bb) {
    //
    return;
  }
};

#endif