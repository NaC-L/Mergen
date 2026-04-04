# Scope

This file owns the support matrix and quality contract. For pipeline order and invariants, use `ARCHITECTURE.md`. For build/test workflow, use `docs/BUILDING.md` and `docs/REWRITE_BASELINE.md`.

## Purpose
Mergen is a function-level LLVM IR lifting engine for deobfuscation and devirtualization of x64 protected functions. It lifts one target function from a PE binary into LLVM IR so downstream optimization and analysis can recover readable control flow and semantics.

## Supported
| Area | Details |
|---|---|
| Architecture | x86-64 PE binaries |
| Instruction set | 115 handlers covering general-purpose integer ops, BMI1/BMI2, bit manipulation, string ops, conditional moves, flag manipulation, and SSE2 integer XMM ops (`MOVDQA`, `PAND`, `POR`, `PXOR`) |
| Control flow | Linear flow, 2-way branches, direct jumps, call/ret, and tested multi-target jump-table shapes (absolute qword, RIP-relative dword offset, shifted-base, shared-target) |
| Output | LLVM IR text suitable for LLVM optimization passes |
| Call-boundary model | Cross-ABI framework for x64 MSVC and x86 cdecl/stdcall/fastcall; `strict` is the operational default, `compat` remains available as a diagnostic fallback |
| Determinism | Canonical naming and golden-hash verification are part of the current contract |

## Unsupported / Known Limitations
| Limitation | Status |
|---|---|
| Floating-point / wider SSE / AVX outside the listed SSE2 integer ops | Not lifted |
| Self-modifying code | Not supported |
| Whole-binary lifting | Out of scope; Mergen is function-level |
| Non-PE formats | Not supported |
| 32-bit x86 lifting | Not supported |
| ARM / RISC-V / other architectures | Not supported |
| Jump-table IR quality | Supported shapes still dispatch on concrete target addresses, not logical case indices |
| Loop-header generalization | Temporarily disabled while the team keeps required VMP 3.8.x targets on the safe high-budget path |

## Tested Protectors
- VMProtect — examples exist; reliability varies by protection level
- Themida — examples exist; reliability varies by protection level

## Quality Contract
- Handler coverage: 112/115 handlers with oracle-backed verification
- Active regression corpus: 32 semantic samples / 176 runtime semantic cases; structured loop recovery now keeps `calc_sum_to_n` and `stack_vm_loop` active, `calc_fib` is CI-skipped on `windows-latest` because the current hosted toolchain still emits a failing loop/codegen shape there, and `calc_cout` remains CI-skipped because its C++ codegen is toolchain-dependent
- Determinism: golden IR hashes are enforced for tracked outputs
- CI gates: register/flag correctness, rewrite baseline, semantic regression, and Windows build lanes
- Targeted VMP gate: `python test.py vmp` must keep required 3.8.x targets at `blocks_completed > 0`; VMP 3.6 remains best-effort only

## Non-goals
- General-purpose decompilation
- Multi-function whole-program recovery
- Broad architecture expansion before x64 protected-function reliability improves
