#pragma once
#include <llvm/Support/raw_ostream.h>
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // _CRT_SECURE_NO_WARNINGS
#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS
#define _SILENCE_ALL_CXX23_DEPRECATION_WARNINGS
#ifndef ZYDIS_STATIC_BUILD
#define ZYDIS_STATIC_BUILD
#endif // ZYDIS_STATIC_BUILD

// #define _NODEV why?

#pragma warning(disable : 4996)
#pragma warning(disable : 4146)

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX
#else
#endif // _WIN32

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"

using Value = llvm::Value;
using Instruction = llvm::Instruction;
using Type = llvm::Type;
using Twine = llvm::Twine;
using ConstantInt = llvm::ConstantInt;
using Constant = llvm::Constant;
using APInt = llvm::APInt;
using BasicBlock = llvm::BasicBlock;
using SelectInst = llvm::SelectInst;

#if LLVM_VERSION_MAJOR < 17
inline llvm::raw_ostream& operator<<(llvm::raw_ostream& OS,
                                     const llvm::KnownBits& KB) {
  KB.print(OS);
  return OS;
}
#endif

#define STACKP_VALUE 0x14FCA8
// if this value changes, its only for debug purposes

using ReverseRegisterMap = llvm::DenseMap<llvm::Value*, int>;
using RegisterMap = llvm::DenseMap<int,
                                   llvm::Value*>; // we dont actually need
                                                  // this to be a map

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
  FLAGS_END = FLAG_IOPL,
  FLAGS_START = FLAG_CF
};

//......
inline llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const Flag flag) {
  switch (flag) {
  case FLAG_CF:
    os << "FLAG_CF";
    break;
  case FLAG_RESERVED1:
    os << "FLAG_RESERVED1";
    break;
  case FLAG_PF:
    os << "FLAG_PF";
    break;
  case FLAG_RESERVED3:
    os << "FLAG_RESERVED3";
    break;
  case FLAG_AF:
    os << "FLAG_AF";
    break;
  case FLAG_RESERVED5:
    os << "FLAG_RESERVED5";
    break;
  case FLAG_ZF:
    os << "FLAG_ZF";
    break;
  case FLAG_SF:
    os << "FLAG_SF";
    break;
  case FLAG_TF:
    os << "FLAG_TF";
    break;
  case FLAG_IF:
    os << "FLAG_IF";
    break;
  case FLAG_DF:
    os << "FLAG_DF";
    break;
  case FLAG_OF:
    os << "FLAG_OF";
    break;
  case FLAG_IOPL:
    os << "FLAG_IOPL";
    break;
  case FLAG_IOPL2:
    os << "FLAG_IOPL2";
    break;
  case FLAG_NT:
    os << "FLAG_NT";
    break;
  case FLAG_MD:
    os << "FLAG_MD";
    break;
  case FLAG_RF:
    os << "FLAG_RF";
    break;
  case FLAG_VM:
    os << "FLAG_VM";
    break;
  case FLAG_AC:
    os << "FLAG_AC";
    break;
  case FLAG_VIF:
    os << "FLAG_VIF";
    break;
  case FLAG_VIP:
    os << "FLAG_VIP";
    break;
  case FLAG_ID:
    os << "FLAG_ID";
    break;
  case FLAG_RES22:
    os << "FLAG_RES22";
    break;
  case FLAG_RES23:
    os << "FLAG_RES23";
    break;
  case FLAG_RES24:
    os << "FLAG_RES24";
    break;
  case FLAG_RES25:
    os << "FLAG_RES25";
    break;
  case FLAG_RES26:
    os << "FLAG_RES26";
    break;
  case FLAG_RES27:
    os << "FLAG_RES27";
    break;
  case FLAG_RES28:
    os << "FLAG_RES28";
    break;
  case FLAG_RES29:
    os << "FLAG_RES29";
    break;
  case FLAG_AES:
    os << "FLAG_AES";
    break;
  case FLAG_AI:
    os << "FLAG_AI";
    break;
  default:
    os << "UNKNOWN_FLAG(" << static_cast<int>(flag) << ")";
    break;
  }
  return os;
}

enum opaque_info { NOT_OPAQUE = 0, OPAQUE_TRUE = 1, OPAQUE_FALSE = 2 };

enum ROP_info {
  ROP_return = 0,
  REAL_return = 1,
};

enum JMP_info {
  JOP_jmp = 0,
  JOP_jmp_unsolved = 1,
};
