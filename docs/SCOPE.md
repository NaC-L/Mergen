# Scope

## Purpose

Mergen is a function-level LLVM IR lifting engine for deobfuscation and devirtualization of x64 protected functions. It translates obfuscated native code into LLVM IR, enabling standard compiler optimizations to recover readable control flow and semantics from virtualized or mutated instruction streams.

## Supported

| Area | Details |
|------|---------|
| Architecture | x86-64 (PE binaries) |
| Instruction set | 115 handlers covering general-purpose integer, BMI1/BMI2, bit manipulation, string ops, conditional moves, flag manipulation, and SSE2 integer XMM ops (`MOVDQA`, `PAND`, `POR`, `PXOR`) |
| Control flow | Linear, conditional branches (2-way), direct jumps, call/ret, multi-target jump tables (absolute qword, RIP-relative dword offset, base-shifted, shared targets) |
| Output | LLVM IR (text), optimizable via LLVM pass pipeline |
| Calling convention awareness | x64 Microsoft ABI (cross-ABI framework: x64 MSVC, x86 cdecl/stdcall/fastcall). Dual-mode: `compat` (default, preserves exploration stability) and `strict` (ABI-enforced clobber/memory effects, opt-in). |
| Optimization profiles | safe, aggressive, debug (planned — Phase 2) |

## Unsupported / Known Limitations

| Limitation | Status |
|------------|--------|
| Indirect jumps with >2 targets (jump tables) | Tested: absolute qword tables, rel32 offset tables, shifted-base tables, shared-target tables, symbolic computation in case bodies. IR quality note: switch dispatches on concrete target addresses, not logical case indices. |
| Floating-point / wider SSE / AVX instructions (outside `MOVDQA`, `PAND`, `POR`, `PXOR`) | Not lifted |
| Self-modifying code | Not supported |
| Multi-function / whole-binary lifting | Single function scope only |
| ELF / Mach-O / non-PE formats | Not supported |
| 32-bit x86 | Not supported |
| ARM / RISC-V / other architectures | Not supported |
| Automatic ABI/prototype normalization | Stage 1 complete (call-boundary ABI contract + dual-mode). Post-lift prototype minimization planned. |
| Full deterministic output | Planned — Phase 3 |

## Tested Protectors

- **VMProtect** — examples exist; reliability varies by protection level.
- **Themida** — examples exist; reliability varies by protection level.

## Quality Contract

- Handler test coverage: 97.4% (112/115 with oracle verification against Unicorn).
- Regression corpus: 28 active samples, 146 semantic test cases, 56 golden IR hashes.
- Jump table coverage: 7 samples across 6 patterns (absolute, rel32, shifted, shared, computation, C-compiled /O2).
- CI gates enforce register and flag correctness.
