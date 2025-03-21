#ifndef COMMON_DISASSEMBLER_H
#define COMMON_DISASSEMBLER_H

#include "CommonMnemonics.h"
#include "CommonRegisters.h"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Mnemonic.h>
#include <Zydis/SharedTypes.h>
#include <concepts>
#include <cstdint>

// #include <string>

enum class OperandType : uint8_t {
  Invalid,
  Register,
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
  // rewrite this to also fit immediate

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