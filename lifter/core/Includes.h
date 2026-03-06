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
#include <magic_enum/magic_enum.hpp>

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

#define STACKP_VALUE 0x00000000014FEA0
// if this value changes, its only for debug purposes

using ReverseRegisterMap = llvm::DenseMap<llvm::Value*, int>;
using RegisterMap = llvm::DenseMap<int,
                                   llvm::Value*>; // we dont actually need
                                                  // this to be a map

enum opaque_info { NOT_OPAQUE = 0, OPAQUE_TRUE = 1, OPAQUE_FALSE = 2 };

enum ROP_info {
  ROP_return = 0,
  REAL_return = 1,
};

enum JMP_info {
  JOP_jmp = 0,
  JOP_jmp_unsolved = 1,
};
