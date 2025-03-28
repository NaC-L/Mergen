#ifndef COMMON_DISASSEMBLER_H
#define COMMON_DISASSEMBLER_H

#include "CommonMnemonics.h"
#include "CommonRegisters.h"
#include "utils.h"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Mnemonic.h>
#include <Zydis/SharedTypes.h>
#include <concepts>
#include <cstdint>
#include <iostream>

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
    UNREACHABLE("invalid size");
  }
  }
  return 0;
}

enum class InstructionPrefix : uint8_t {
  None = 0,
  Rep,
  Repe,
  Repne,
  Lock,
  End = Lock
};

// This unified structure is meant to capture common disassembly information
// In the future, we might need to extend this
struct MergenDisassembledInstruction {
  // instruction mnemonic
  Mnemonic mnemonic;

  // we only care about explicit operands in this struct

  // we can do this because x86 allows maximum of one mem operand

  Register mem_base;
  Register mem_index;
  uint8_t mem_scale;

  union {
    uint64_t mem_disp;
    uint64_t immediate2;
  };

  uint8_t stack_growth;

  // TODO : 32 bit
  uint64_t immediate; //

  Register regs[4];
  OperandType types[4];

  // instruction prefix, attributes
  uint64_t attributes;

  uint8_t length;
  uint8_t operand_count_visible;
  // std::string text;
};

template <typename T>
concept Disassembler = requires(T d, void* buffer, size_t size) {
  {
    d.disassemble(buffer, size)
  } -> std::same_as<MergenDisassembledInstruction>;
};

template <Disassembler T>
inline MergenDisassembledInstruction runDisassembler(T& dis, void* buffer,
                                                     size_t size = 15) {
  return dis.disassemble(buffer, size);
}

#endif // COMMON_DISASSEMBLER_H