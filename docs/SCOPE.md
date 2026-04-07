# Scope

This file owns the support matrix and quality contract. For pipeline order and invariants, use `ARCHITECTURE.md`. For build/test workflow, use `docs/BUILDING.md` and `docs/REWRITE_BASELINE.md`.

## Purpose
Mergen is a function-level LLVM IR lifting engine for deobfuscation and devirtualization of x64 protected functions. It lifts one target function from a PE binary into LLVM IR so downstream optimization and analysis can recover readable control flow and semantics.

## Supported
| Area | Details |
|---|---|
| Architecture | x86-64 PE binaries |
| Instruction set | 119 handlers covering general-purpose integer ops, BMI1/BMI2, bit manipulation, string ops, conditional moves, flag manipulation, and SSE2 integer XMM ops (`MOVDQA`, `MOVQ`, `PUNPCKLQDQ`, `PAND`, `POR`, `PXOR`) |
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

## Current Development Focus
- Near term: broaden control-flow recovery and IR quality for loops, jump tables, indirect branches, and VM-style dispatcher shapes.
- Later: expand 128-bit register/instruction coverage beyond the current SSE2 integer XMM subset once the control-flow path is stable enough to carry the added surface area.

## Tested Protectors
- VMProtect — examples exist; reliability varies by protection level
- Themida — examples exist; reliability varies by protection level

## Quality Contract
- Handler coverage: 115/119 handlers covered by the full-handler oracle suite, with 4 intentional skips (`cpuid`, `rdtsc`, `ret`, `scasx`)
- Active regression corpus: 31 semantic samples / 175 runtime semantic cases in CI; `calc_cout`, `calc_sum_to_n`, and `stack_vm_loop` are active under the current safe path; `calc_fib` and `calc_sum_array` remain `ci_skip` because windows-latest clang-cl emits a codegen shape the lifter cannot yet handle (tracked as a follow-up; local clean Release builds lift them correctly)
- Determinism: golden IR hashes are enforced for tracked outputs
- CI gates: register/flag correctness, rewrite baseline, semantic regression, and Windows build lanes
- Targeted VMP gate: `python test.py vmp` must keep required 3.8.x targets at `blocks_completed > 0`; VMP 3.6 remains best-effort only

## Non-goals
- General-purpose decompilation
- Multi-function whole-program recovery
- Broad architecture expansion before x64 protected-function reliability improves
- Broad 128-bit register/instruction expansion before control-flow reliability improves
