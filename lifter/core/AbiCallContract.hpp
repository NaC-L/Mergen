#ifndef ABI_CALL_CONTRACT_H
#define ABI_CALL_CONTRACT_H

#include "CommonRegisters.h"
#include <array>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <string_view>
#include <vector>

// --- ABI kind ---
enum class AbiKind : uint8_t {
  X64_MSVC,      // Microsoft x64 (Win64)
  X86_CDECL,     // x86 __cdecl
  X86_STDCALL,   // x86 __stdcall
  X86_FASTCALL,  // x86 __fastcall
  Unknown,       // No ABI information available
};

// --- Call-model mode ---
// Controls how aggressive the lifter is at enforcing ABI semantics.
//   Compat  — preserve current behavior: no clobber, no memory effect.
//   Strict  — apply volatile clobber + memory effects per ABI.
enum class CallModelMode : uint8_t {
  Compat,
  Strict,
};

// --- Stack cleanup convention ---
enum class StackCleanup : uint8_t {
  Caller,   // Caller adjusts RSP after call (cdecl, x64)
  Callee,   // Callee pops args via `ret imm` (stdcall, fastcall)
  None,     // No stack adjustment needed (0-arg, thunk)
  Unknown,  // Cannot determine
};

// --- Memory effect ---
enum class CallMemoryEffect : uint8_t {
  Preserve,       // Assume call does not modify memory visible to lifter
  MayReadWrite,   // Assume call may read/write any memory
};

// --- Call target classification ---
enum class CallTargetClass : uint8_t {
  KnownByName,       // Resolved via FunctionSignatures name lookup
  KnownByAddress,    // Resolved via FunctionSignatures address lookup
  KnownBySig,        // Resolved via byte-pattern signature match
  UnknownDirect,     // Constant target, no signature info
  UnknownIndirect,   // Register/memory-indirect target
};

// --- Register set helper ---
// Small fixed-capacity set of register IDs.  Avoids heap allocation for the
// common case (x64 volatile set = 9 GPRs + 6 XMMs = 15 entries).
template <typename Register>
struct RegSet {
  static constexpr size_t MAX_REGS = 32;
  std::array<Register, MAX_REGS> regs{};
  uint8_t count = 0;

  constexpr RegSet() = default;

  constexpr RegSet(std::initializer_list<Register> list) {
    for (auto r : list) {
      regs[count++] = r;
    }
  }

  constexpr bool contains(Register r) const {
    for (uint8_t i = 0; i < count; ++i) {
      if (regs[i] == r) return true;
    }
    return false;
  }

  constexpr const Register* begin() const { return regs.data(); }
  constexpr const Register* end()   const { return regs.data() + count; }
  constexpr uint8_t size()          const { return count; }
  constexpr bool    empty()         const { return count == 0; }
};

// --- Call effects ---
// Describes the full ABI contract at a single call site.
template <typename Register>
struct CallEffects {
  AbiKind          abi       = AbiKind::Unknown;
  CallTargetClass  target    = CallTargetClass::UnknownIndirect;
  StackCleanup     cleanup   = StackCleanup::Unknown;
  CallMemoryEffect memory    = CallMemoryEffect::Preserve;

  // Argument-passing registers (in ABI order).
  RegSet<Register> argRegs;

  // Return registers.
  RegSet<Register> retRegs;

  // Volatile (caller-saved) registers — destroyed by the call.
  RegSet<Register> volatileRegs;

  // Stack delta applied by caller after the call instruction.
  // For x64 MSVC this is typically 0 (shadow space is not adjusted by
  // the lifter).  For cdecl, it would be argCount * ptrSize.
  int32_t callerStackDelta = 0;
};

// ──────────────────────────────────────────────────────────────────
// Pre-built ABI descriptors
// ──────────────────────────────────────────────────────────────────

namespace abi {

// Microsoft x64 argument registers (integer)
template <typename R>
constexpr RegSet<R> x64MsvcArgRegs() {
  return {R::RCX, R::RDX, R::R8, R::R9};
}

// Microsoft x64 return register
template <typename R>
constexpr RegSet<R> x64MsvcRetRegs() {
  return {R::RAX};
}

// Microsoft x64 volatile (caller-saved) GPRs
// RAX, RCX, RDX, R8–R11 are volatile.
// XMM0–XMM5 are volatile but we only track GPRs here since the lifter
// doesn't yet model XMM state across calls.
template <typename R>
constexpr RegSet<R> x64MsvcVolatileGPRs() {
  return {R::RAX, R::RCX, R::RDX, R::R8, R::R9, R::R10, R::R11};
}

// x86 cdecl: all args on stack, caller cleanup
template <typename R>
constexpr RegSet<R> x86CdeclArgRegs() {
  return {};  // all on stack
}

// x86 volatile GPRs (EAX, ECX, EDX are volatile in all x86 CCs)
template <typename R>
constexpr RegSet<R> x86VolatileGPRs() {
  return {R::RAX, R::RCX, R::RDX};  // using 64-bit names; lifter truncates
}

// ──────────────────────────────────────────────────────────────────
// Factory: build CallEffects for a given ABI + mode
// ──────────────────────────────────────────────────────────────────

// Build the default CallEffects for an *unknown* call target under the
// specified ABI and mode.  Known calls will override specific fields.
template <typename Register>
inline CallEffects<Register>
buildUnknownCallEffects(AbiKind abi, CallModelMode mode) {
  CallEffects<Register> fx;
  fx.abi    = abi;
  fx.target = CallTargetClass::UnknownDirect;

  switch (abi) {
  case AbiKind::X64_MSVC: {
    fx.argRegs      = x64MsvcArgRegs<Register>();
    fx.retRegs      = x64MsvcRetRegs<Register>();
    fx.cleanup      = StackCleanup::Caller;
    fx.callerStackDelta = 0; // lifter doesn't model shadow space

    if (mode == CallModelMode::Strict) {
      fx.volatileRegs = x64MsvcVolatileGPRs<Register>();
      fx.memory       = CallMemoryEffect::MayReadWrite;
    } else {
      // Compat: no clobber, memory preserved — matches legacy behavior
      fx.volatileRegs = {};
      fx.memory       = CallMemoryEffect::Preserve;
    }
    break;
  }
  case AbiKind::X86_CDECL: {
    fx.argRegs      = x86CdeclArgRegs<Register>();
    fx.retRegs      = {Register::RAX};
    fx.cleanup      = StackCleanup::Caller;

    if (mode == CallModelMode::Strict) {
      fx.volatileRegs = x86VolatileGPRs<Register>();
      fx.memory       = CallMemoryEffect::MayReadWrite;
    } else {
      fx.volatileRegs = {};
      fx.memory       = CallMemoryEffect::Preserve;
    }
    break;
  }
  case AbiKind::X86_STDCALL: {
    fx.argRegs      = {};  // all on stack
    fx.retRegs      = {Register::RAX};
    fx.cleanup      = StackCleanup::Callee;

    if (mode == CallModelMode::Strict) {
      fx.volatileRegs = x86VolatileGPRs<Register>();
      fx.memory       = CallMemoryEffect::MayReadWrite;
    } else {
      fx.volatileRegs = {};
      fx.memory       = CallMemoryEffect::Preserve;
    }
    break;
  }
  case AbiKind::X86_FASTCALL: {
    fx.argRegs      = {Register::RCX, Register::RDX};
    fx.retRegs      = {Register::RAX};
    fx.cleanup      = StackCleanup::Callee;

    if (mode == CallModelMode::Strict) {
      fx.volatileRegs = x86VolatileGPRs<Register>();
      fx.memory       = CallMemoryEffect::MayReadWrite;
    } else {
      fx.volatileRegs = {};
      fx.memory       = CallMemoryEffect::Preserve;
    }
    break;
  }
  case AbiKind::Unknown:
  default: {
    // Safest default: assume x64 MSVC layout (the primary target).
    fx.argRegs      = x64MsvcArgRegs<Register>();
    fx.retRegs      = x64MsvcRetRegs<Register>();
    fx.cleanup      = StackCleanup::Caller;

    if (mode == CallModelMode::Strict) {
      fx.volatileRegs = x64MsvcVolatileGPRs<Register>();
      fx.memory       = CallMemoryEffect::MayReadWrite;
    } else {
      fx.volatileRegs = {};
      fx.memory       = CallMemoryEffect::Preserve;
    }
    break;
  }
  }
  return fx;
}

// ──────────────────────────────────────────────────────────────────
// Stack delta helper for ret-instruction alignment
// ──────────────────────────────────────────────────────────────────

// Returns the number of bytes the ret instruction should pop beyond the
// return address.  For stdcall/fastcall this comes from `ret imm16`.
// For cdecl/x64, it should be 0.
inline int32_t expectedRetImmediate(StackCleanup cleanup) {
  // The actual immediate is instruction-specific; this helper encodes the
  // *expectation*: callee-cleanup ABIs produce nonzero ret imm.
  // Zero means no callee cleanup expected.
  switch (cleanup) {
  case StackCleanup::Callee:
    return -1; // caller must read actual ret imm from instruction
  case StackCleanup::Caller:
  case StackCleanup::None:
  case StackCleanup::Unknown:
  default:
    return 0;
  }
}

// ──────────────────────────────────────────────────────────────────
// Diagnostics
// ──────────────────────────────────────────────────────────────────

inline const char* abiKindName(AbiKind k) {
  switch (k) {
  case AbiKind::X64_MSVC:     return "x64_msvc";
  case AbiKind::X86_CDECL:    return "x86_cdecl";
  case AbiKind::X86_STDCALL:  return "x86_stdcall";
  case AbiKind::X86_FASTCALL: return "x86_fastcall";
  case AbiKind::Unknown:      return "unknown";
  }
  return "?";
}

inline const char* callModelModeName(CallModelMode m) {
  switch (m) {
  case CallModelMode::Compat: return "compat";
  case CallModelMode::Strict: return "strict";
  }
  return "?";
}

inline const char* callTargetClassName(CallTargetClass c) {
  switch (c) {
  case CallTargetClass::KnownByName:    return "known_name";
  case CallTargetClass::KnownByAddress: return "known_addr";
  case CallTargetClass::KnownBySig:     return "known_sig";
  case CallTargetClass::UnknownDirect:  return "unknown_direct";
  case CallTargetClass::UnknownIndirect:return "unknown_indirect";
  }
  return "?";
}

inline const char* stackCleanupName(StackCleanup s) {
  switch (s) {
  case StackCleanup::Caller:  return "caller";
  case StackCleanup::Callee:  return "callee";
  case StackCleanup::None:    return "none";
  case StackCleanup::Unknown: return "unknown";
  }
  return "?";
}

inline const char* callMemoryEffectName(CallMemoryEffect e) {
  switch (e) {
  case CallMemoryEffect::Preserve:     return "preserve";
  case CallMemoryEffect::MayReadWrite: return "may_read_write";
  }
  return "?";
}

template <typename Register>
inline void printCallEffectsDiag(const CallEffects<Register>& fx,
                                 uint64_t callAddr) {
  std::cout << "[call-abi] 0x" << std::hex << callAddr << std::dec
            << " target=" << callTargetClassName(fx.target)
            << " abi=" << abiKindName(fx.abi)
            << " cleanup=" << stackCleanupName(fx.cleanup)
            << " memory=" << callMemoryEffectName(fx.memory)
            << " clobbers=" << static_cast<int>(fx.volatileRegs.size())
            << "\n" << std::flush;
}

} // namespace abi

#endif // ABI_CALL_CONTRACT_H
