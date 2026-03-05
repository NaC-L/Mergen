# Scope

## Purpose

Mergen is a function-level LLVM IR lifting engine for deobfuscation and devirtualization of x64 protected functions. It translates obfuscated native code into LLVM IR, enabling standard compiler optimizations to recover readable control flow and semantics from virtualized or mutated instruction streams.

## Supported

| Area | Details |
|------|---------|
| Architecture | x86-64 (PE binaries) |
| Instruction set | 111 handlers covering general-purpose integer, BMI1/BMI2, bit manipulation, string ops, conditional moves, flag manipulation |
| Control flow | Linear, conditional branches (2-way), direct jumps, call/ret |
| Output | LLVM IR (text), optimizable via LLVM pass pipeline |
| Calling convention awareness | x64 Microsoft (manual signature fixup may be needed) |
| Optimization profiles | safe, aggressive, debug (planned — Phase 2) |

## Unsupported / Known Limitations

| Limitation | Status |
|------------|--------|
| Indirect jumps with >2 targets (jump tables) | Active work area |
| Floating-point / SSE / AVX instructions | Not lifted |
| Self-modifying code | Not supported |
| Multi-function / whole-binary lifting | Single function scope only |
| ELF / Mach-O / non-PE formats | Not supported |
| 32-bit x86 | Not supported |
| ARM / RISC-V / other architectures | Not supported |
| Automatic ABI/prototype normalization | Planned — Phase 2 |
| Full deterministic output | Planned — Phase 3 |

## Tested Protectors

- **VMProtect** — examples exist; reliability varies by protection level.
- **Themida** — examples exist; reliability varies by protection level.

## Quality Contract

- Handler test coverage: 97% (108/111 with oracle verification against Unicorn).
- CI gates enforce register and flag correctness.
