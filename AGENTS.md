# Repository Guidelines

## Project Overview
Mergen is a function-level x64 PE to LLVM IR lifter for deobfuscation and devirtualization. The active workflow is rewrite/regression driven: changes are expected to preserve lifted IR shape, runtime semantics, and deterministic outputs.

Primary repo entry points:
- `README.md` — project purpose and high-level entry links
- `ARCHITECTURE.md` — current pipeline order and invariants
- `docs/SCOPE.md` — support matrix and quality contract
- `docs/REWRITE_BASELINE.md` — operational regression workflow

## Architecture & Data Flow
The core pipeline is:
1. CLI entry in `lifter/core/Lifter.cpp`
2. Runtime image validation in `lifter/core/RuntimeImageContext.hpp`
3. Lifter setup / auto-outline in `lifter/core/LifterStages.hpp`
4. Memory policy + paged memory setup in `lifter/memory/MemoryPolicySetup.hpp` and `lifter/core/LifterPipelineStages.hpp`
5. Signature stage in `lifter/core/LifterPipelineStages.hpp`
6. Lift loop in `lifter/core/LiftDriver.hpp`
7. Fixpoint optimization in `lifter/core/MergenPB.hpp`
8. Final post-passes and IR emission

Important invariants:
- `STACKP_VALUE` is fixed at `0x14FEA0` (`lifter/core/Includes.h`).
- Stack reserve is clamped to `[0x1000, 0x100000]` (`lifter/memory/MemoryPolicySetup.hpp`).
- Pass order is intentional: `GEPLoadPass -> ReplaceTruncWithLoadPass -> PromotePseudoStackPass -> PromotePseudoMemory`, then O2, then post-passes such as switch normalization and canonical naming (`ARCHITECTURE.md`, `lifter/core/MergenPB.hpp`). Do not reorder casually.
- The disassembler boundary is normalized through `lifter/disasm/CommonDisassembler.hpp`; semantics should consume normalized operands, not backend-specific details.

## Key Directories
- `lifter/core/` — CLI, runtime image setup, pipeline orchestration, ABI/signature handling
- `lifter/semantics/` — opcode dispatch and instruction semantics (`Semantics.ipp`, `Semantics_*.ipp`, `x86_64_opcodes.x`)
- `lifter/disasm/` — Iced/Zydis abstraction layer
- `lifter/memory/` — file-backed memory, page map, pseudo-memory/stack promotion
- `lifter/analysis/` — custom LLVM passes and path solving
- `lifter/test/` — in-process instruction/oracle test harness and golden metadata
- `testcases/rewrite_smoke/` — rewrite smoke corpus sources
- `scripts/rewrite/` — baseline gate, sample build, manifest validation, oracle generation, semantic checks
- `scripts/dev/` — preferred configure/build entrypoints
- `docs/` — current workflow, scope, and reviewer policy docs

## Important Files
- `cmake.toml` — source of truth for build configuration; `CMakeLists.txt` is generated, do not edit it directly.
- `test.py` — primary QA entrypoint.
- `scripts/rewrite/instruction_microtests.json` — source of truth for rewrite smoke samples, expected IR patterns, semantic cases, and CI skips.
- `lifter/test/test_vectors/oracle_vectors.json` — default instruction oracle vectors.
- `lifter/test/test_vectors/golden_ir_hashes.json` — determinism gate for tracked IR outputs.
- `.editorconfig` and `.clang-format` — formatting contract (2 spaces, LF, UTF-8, 100-column LLVM-based style).

## Development Commands
Before running any command in this section, confirm the exact repo root and cwd. Prefer these repo-provided scripts over ad hoc shell commands.

Preferred Windows build flow:
```bat
cmd /c scripts\dev\configure_iced.cmd
cmd /c scripts\dev\build_iced.cmd
```

Alternate Zydis-only lane:
```bat
cmd /c scripts\dev\configure_zydis.cmd
cmd /c scripts\dev\build_zydis.cmd
```

Primary test commands:
```bat
python test.py quick
python test.py all
python test.py baseline
python test.py micro --check-flags
python test.py negative
python test.py coverage --full
python test.py report --json
```

Useful targeted flows:
```bat
python test.py micro add
python test.py semantic branch
scripts\rewrite\run.cmd
scripts\rewrite\run_microtests.cmd --check-flags xor
```

## Runtime / Tooling Preferences
- Platform focus is Windows. CI uses `scripts/dev/*.cmd` and `windows-latest`.
- Prefer the iced lane by default; use Zydis only when you need the fallback/backend-specific lane.
- Configure/build scripts assume Ninja + `clang-cl`; they do not invoke `VsDevCmd.bat`.
- `LLVM_DIR` must resolve to LLVM 18; CI currently downloads LLVM 18.1.8.
- Cargo is expected on PATH for the iced lane.
- Build outputs live in `build_iced/`, `build_zydis/`, or other `build*/` directories; treat them as generated artifacts.
- Regression artifacts are written outside the repo by default to `../rewrite-regression-work/`.

## Code Conventions & Common Patterns
- Extend instruction support through the existing opcode table and semantics files; do not add parallel dispatch paths.
  - Wire new entries in `lifter/semantics/x86_64_opcodes.x`.
  - Implement behavior in the appropriate `Semantics_*.ipp` file.
- Preserve the normalized operand model across disassembly and semantics. Cross-check `lifter/disasm/CommonDisassembler.hpp`, backend adapters, and downstream helpers before changing operand enums or widths.
- Memory accesses should go through the existing operand/memory helpers (`lifter/semantics/OperandUtils.ipp`); bypassing them usually breaks constant folding, page-map behavior, or pseudo-stack promotion.
- Call handling is ABI-aware. Check `lifter/core/AbiCallContract.hpp` and existing control-flow helpers before changing call lowering.
- Prefer explicit failures and diagnostics over silent fallbacks. The repo already has structured lift diagnostics (`lifter/core/LiftDiagnostics.hpp`) and strict negative tests in `test.py`.
- When touching build definitions, update `cmake.toml`; regenerate behavior flows through cmkr into `CMakeLists.txt`.
- Keep docs and test manifests in the same change when behavior changes. This repo relies on docs/tests as active contracts, not afterthoughts.

## Testing & QA Expectations
- `python test.py` is the canonical entrypoint. `quick` and `all` are the main gates used in CI.
- The rewrite baseline is manifest-backed: every source in `testcases/rewrite_smoke/` must have exactly one manifest entry in `scripts/rewrite/instruction_microtests.json`.
- Golden IR hashing is part of the contract. C/C++-compiled smoke samples are excluded from golden hashes because their IR addresses are toolchain-dependent; they are checked via semantic tests instead.
- `python test.py negative` matters: it guards explicit failure behavior for malformed manifests, unsafe paths, and bad vector schemas.
- Use focused verification that matches your change:
  - Core/semantics/disasm/test harness changes: `python test.py micro --check-flags`
  - Rewrite script/manifest changes: `python test.py baseline` and `python test.py negative`
  - Coverage/vector plumbing: `python test.py coverage --full` and `python test.py report --json`
  - Build script/CMake changes: rerun the affected `scripts\dev\configure_*.cmd` + `build_*.cmd` lane

## Operator workflow defaults

> Use these with the repo-specific architecture/test rules above.

- Confirm the real repo root, source-of-truth file, and owning subsystem before searching or editing.
- Narrow search scope before using broad repo scans.
- Prefer `read`, `find`, `grep`, `ast_grep`, `edit`, `ast_edit`, and `lsp` before bash for discovery or structural edits.
- Before build/test/git/bash commands, confirm the exact cwd and lane you intend to run.
- If you edit the same file twice, re-read it first.
- Default to one main line of work; split into subtasks only when file boundaries are real and outputs are independent.
- Do not finish non-trivial work without focused verification that matches the changed subsystem.
- Before comparing two branches with `python test.py baseline`/`quick`, wipe `build_iced/` (`rm -rf build_iced && cmd /c scripts\dev\configure_iced.cmd && cmd /c scripts\dev\build_iced.cmd`).  Incremental builds reuse object files across branches and will happily link a stale mix of old and new code, producing a lifter binary whose failure set reflects neither branch.  This has caused at least one false "branch matches main" claim.

## What not to do
- Do not start with repo-root scans when a narrower directory or entry document can answer the question.
- Do not run configure/build/test commands from an assumed cwd.
- Do not use bash-first discovery when a specialized tool can answer it.
- Do not spawn reviewer/subtask branches just to spread a single code path across multiple agents.

## Process Notes For AI Assistants
- Prefer `docs/REWRITE_BASELINE.md` and CI workflows over older generic build docs when commands disagree.
- Do not edit generated files or artifact outputs unless the task is explicitly about generation.
- Before changing exported behavior, inspect direct consumers and the matching rewrite/test manifests.
- If you add a new sample, update both `testcases/rewrite_smoke/` and `scripts/rewrite/instruction_microtests.json` in the same change.
- If you change semantics or ABI behavior, expect to update oracle vectors, microtests, semantic expectations, and possibly golden hashes.
