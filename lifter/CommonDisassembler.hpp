#ifndef COMMON_DISASSEMBLER_H
#define COMMON_DISASSEMBLER_H

#include "CommonMnemonics.h"
#include "CommonRegisters.h"
#include "ZydisDisassembler_mnemonics.h"
#include "ZydisDisassembler_registers.h"
#include <array>
#include <concepts>
#include <cstdint>
#include <string>

// #include <string>

enum class OperandType : uint8_t {
  Invalid,
  Register8,
  Register16,
  Register32,
  Register64,
  Memory8,
  Memory16,
  Memory32,
  Memory64,
  Immediate8,
  Immediate8_2nd, // enter/exit
  Immediate16,
  Immediate32,
  Immediate64,
  End = Immediate64
};

inline uint8_t GetTypeSize(OperandType op) {
  switch (op) {
  case OperandType::Register8:
  case OperandType::Memory8:
  case OperandType::Immediate8:
  case OperandType::Immediate8_2nd: {
    return 8;
  }
  case OperandType::Register16:
  case OperandType::Memory16:
  case OperandType::Immediate16: {
    return 16;
  }
  case OperandType::Register32:
  case OperandType::Memory32:
  case OperandType::Immediate32: {
    return 32;
  }
  case OperandType::Register64:
  case OperandType::Memory64:
  case OperandType::Immediate64: {
    return 64;
  }
  default: {
    // UNREACHABLE("invalid size");
  }
  }
  return 0;
}

template <Registers Register> Register getBiggestEncoding(Register reg) {

  switch (reg) {

  case Register::AL:
  case Register::AH:
  case Register::AX:
  case Register::EAX:
  case Register::RAX:
    return Register::RAX;

  case Register::CL:
  case Register::CH:
  case Register::CX:
  case Register::ECX:
  case Register::RCX:
    return Register::RCX;

  case Register::DL:
  case Register::DH:
  case Register::DX:
  case Register::EDX:
  case Register::RDX:
    return Register::RDX;

  case Register::BL:
  case Register::BH:
  case Register::BX:
  case Register::EBX:
  case Register::RBX:
    return Register::RBX;

  case Register::SPL:
  case Register::SP:
  case Register::ESP:
  case Register::RSP:
    return Register::RSP;

  case Register::BPL:
  case Register::BP:
  case Register::EBP:
  case Register::RBP:
    return Register::RBP;

  case Register::SIL:
  case Register::SI:
  case Register::ESI:
  case Register::RSI:
    return Register::RSI;

  case Register::DIL:
  case Register::DI:
  case Register::EDI:
  case Register::RDI:
    return Register::RDI;

  case Register::R8B:
  case Register::R8W:
  case Register::R8D:
  case Register::R8:
    return Register::R8;

  case Register::R9B:
  case Register::R9W:
  case Register::R9D:
  case Register::R9:
    return Register::R9;

  case Register::R10B:
  case Register::R10W:
  case Register::R10D:
  case Register::R10:
    return Register::R10;

  case Register::R11B:
  case Register::R11W:
  case Register::R11D:
  case Register::R11:
    return Register::R11;

  case Register::R12B:
  case Register::R12W:
  case Register::R12D:
  case Register::R12:
    return Register::R12;

  case Register::R13B:
  case Register::R13W:
  case Register::R13D:
  case Register::R13:
    return Register::R13;

  case Register::R14B:
  case Register::R14W:
  case Register::R14D:
  case Register::R14:
    return Register::R14;

  case Register::R15B:
  case Register::R15W:
  case Register::R15D:
  case Register::R15:
    return Register::R15;

  case Register::EFLAGS:
  case Register::RFLAGS:
    return Register::RFLAGS;

  case Register::EIP:
  case Register::RIP:
    return Register::RIP;

  default:
    return Register::None;
  }
}

template <Registers Register>
inline Register getRegOfSize(Register reg, uint8_t size) {

  auto size2index = [](uint8_t size) {
    switch (size) {
    case 64:
      return 3;
    case 32:
      return 2;
    case 16:
      return 1;
    case 8:
      return 0;
    }

    return -1;
  };

  uint8_t index = size2index(size);
  // pray god this is inlined so this switch case is optimized out
  switch (reg) {

  case Register::AL:
  case Register::AH:
  case Register::AX:
  case Register::EAX:
  case Register::RAX:
    return std::array{Register::AL, Register::AX, Register::EAX,
                      Register::RAX}[index];

  case Register::CL:
  case Register::CH:
  case Register::CX:
  case Register::ECX:
  case Register::RCX:
    return std::array{Register::CL, Register::CX, Register::ECX,
                      Register::RCX}[index];

  case Register::DL:
  case Register::DH:
  case Register::DX:
  case Register::EDX:
  case Register::RDX:
    return std::array{Register::DL, Register::DX, Register::EDX,
                      Register::RDX}[index];

  case Register::BL:
  case Register::BH:
  case Register::BX:
  case Register::EBX:
  case Register::RBX:
    return std::array{Register::BL, Register::BX, Register::EBX,
                      Register::RBX}[index];

  case Register::SPL:
  case Register::SP:
  case Register::ESP:
  case Register::RSP:
    return std::array{Register::SPL, Register::SP, Register::ESP,
                      Register::RSP}[index];

  case Register::BPL:
  case Register::BP:
  case Register::EBP:
  case Register::RBP:
    return std::array{Register::BPL, Register::BP, Register::EBP,
                      Register::RBP}[index];

  case Register::SIL:
  case Register::SI:
  case Register::ESI:
  case Register::RSI:
    return std::array{Register::SIL, Register::SI, Register::ESI,
                      Register::RSI}[index];

  case Register::DIL:
  case Register::DI:
  case Register::EDI:
  case Register::RDI:
    return std::array{Register::DIL, Register::DI, Register::EDI,
                      Register::RDI}[index];

  case Register::R8B:
  case Register::R8W:
  case Register::R8D:
  case Register::R8:
    return std::array{Register::R8B, Register::R8W, Register::R8D,
                      Register::R8}[index];

  case Register::R9B:
  case Register::R9W:
  case Register::R9D:
  case Register::R9:
    return std::array{Register::R9B, Register::R9W, Register::R9D,
                      Register::R9}[index];

  case Register::R10B:
  case Register::R10W:
  case Register::R10D:
  case Register::R10:
    return std::array{Register::R10B, Register::R10W, Register::R10D,
                      Register::R10}[index];

  case Register::R11B:
  case Register::R11W:
  case Register::R11D:
  case Register::R11:
    return std::array{Register::R11B, Register::R11W, Register::R11D,
                      Register::R11}[index];

  case Register::R12B:
  case Register::R12W:
  case Register::R12D:
  case Register::R12:
    return std::array{Register::R12B, Register::R12W, Register::R12D,
                      Register::R12}[index];

  case Register::R13B:
  case Register::R13W:
  case Register::R13D:
  case Register::R13:
    return std::array{Register::R13B, Register::R13W, Register::R13D,
                      Register::R13}[index];

  case Register::R14B:
  case Register::R14W:
  case Register::R14D:
  case Register::R14:
    return std::array{Register::R14B, Register::R14W, Register::R14D,
                      Register::R14}[index];

  case Register::R15B:
  case Register::R15W:
  case Register::R15D:
  case Register::R15:
    return std::array{Register::R15B, Register::R15B, Register::R15D,
                      Register::R15}[index];

  case Register::EFLAGS:
  case Register::RFLAGS:
    return std::array{Register::None, Register::None, Register::EFLAGS,
                      Register::RFLAGS}[index];

  case Register::EIP:
  case Register::RIP:
    return std::array{Register::None, Register::None, Register::EIP,
                      Register::RIP}[index];

  default:
    return Register::None;
  }
}

template <Registers Register> inline uint8_t getRegisterSize(Register reg) {

  switch (reg) {
  case Register::RAX:
  case Register::RCX:
  case Register::RDX:
  case Register::RBX:
  case Register::RSP:
  case Register::RBP:
  case Register::RSI:
  case Register::RDI:
  case Register::R8:
  case Register::R9:
  case Register::R10:
  case Register::R11:
  case Register::R12:
  case Register::R13:
  case Register::R14:
  case Register::R15:
  case Register::RIP:
  case Register::RFLAGS:
    return 64;

  case Register::EAX:
  case Register::ECX:
  case Register::EDX:
  case Register::EBX:
  case Register::ESP:
  case Register::EBP:
  case Register::ESI:
  case Register::EDI:
  case Register::R8D:
  case Register::R9D:
  case Register::R10D:
  case Register::R11D:
  case Register::R12D:
  case Register::R13D:
  case Register::R14D:
  case Register::R15D:
  case Register::EIP:
  case Register::EFLAGS:
    return 32;

  case Register::AX:
  case Register::CX:
  case Register::DX:
  case Register::BX:
  case Register::SP:
  case Register::BP:
  case Register::SI:
  case Register::DI:
  case Register::R8W:
  case Register::R9W:
  case Register::R10W:
  case Register::R11W:
  case Register::R12W:
  case Register::R13W:
  case Register::R14W:
  case Register::R15W:
    return 16;

  case Register::AL:
  case Register::AH:
  case Register::CL:
  case Register::CH:
  case Register::DL:
  case Register::DH:
  case Register::BL:
  case Register::BH:
  case Register::SPL:
  case Register::BPL:
  case Register::SIL:
  case Register::DIL:
  case Register::R8B:
  case Register::R9B:
  case Register::R10B:
  case Register::R11B:
  case Register::R12B:
  case Register::R13B:
  case Register::R14B:
  case Register::R15B:
    return 8;
  default:
    return 0;
  }
}

enum class InstructionPrefix : uint8_t {
  None = 0,
  Rep,
  Repe = Rep,
  Repne,
  Lock,
  End = Lock
};

// This unified structure is meant to capture common disassembly information
// In the future, we might need to extend this

template <Mnemonics Mnemonic = MnemonicInternal,
          Registers Register = RegisterInternal>
struct MergenDisassembledInstruction_base {

  // we only care about explicit operands in this struct

  // we can do this because x86 allows maximum of one mem operand

  Register mem_base;
  Register mem_index;
  uint8_t mem_scale;

  uint8_t stack_growth;

  Register regs[4];
  OperandType types[4];

  // instruction prefix, attributes
  InstructionPrefix attributes;

  uint8_t length;
  uint8_t operand_count_visible;

  // instruction mnemonic
  Mnemonic mnemonic;

  // TODO : 32 bit
  uint64_t immediate; //

  union {
    uint64_t mem_disp;
    uint64_t immediate2;
  };

#ifndef _NODEV
  std::string text;
#endif
};

// using MergenDisassembledInstruction = MergenDisassembledInstruction_base<>;

template <typename T, typename T2, typename T3>
concept Disassembler = requires(T d, void* buffer, size_t size) {
  {
    d.disassemble(buffer, size)
  } -> std::same_as<MergenDisassembledInstruction_base<T2, T3>>;
};

template <typename T, typename T2 = MnemonicInternal,
          typename T3 = RegisterInternal>
  requires Disassembler<T, T2, T3>
inline MergenDisassembledInstruction_base<T2, T3>
runDisassembler(T& dis, void* buffer, size_t size = 15) {
  return dis.disassemble(buffer, size);
}

#endif // COMMON_DISASSEMBLER_H