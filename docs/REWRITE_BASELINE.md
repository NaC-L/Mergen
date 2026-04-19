# Rewrite Baseline and Regression Workflow

This document defines the baseline checks that must stay green during the rewrite.

## Scope

The rewrite baseline validates every sample declared in `scripts/rewrite/instruction_microtests.json` and enforces one-to-one coverage with `testcases/rewrite_smoke/*`.
Current manifest coverage includes branch/stack/indirect control-flow samples, arithmetic micro-samples, loop/nested-branch/switch patterns, and C/C++ smoke targets (`calc_*`).

Sample sources live in:

- `testcases/rewrite_smoke/*.asm`
- `testcases/rewrite_smoke/*.c`
- `testcases/rewrite_smoke/*.cpp`

## Script layout

- `scripts/rewrite/build_samples.cmd` — assembles/links rewrite smoke samples with incremental timestamp checks (rebuilds only when source is newer than obj/exe/map) using `clang-cl`; jump-table C samples compile in the dedicated `/O2` pass only
- `scripts/rewrite/instruction_microtests.json` — source of truth for sample symbols, expected IR patterns, and runtime semantic test cases
- `scripts/rewrite/run.ps1` — builds samples, clears stale `ir_outputs/*.ll` artifacts, runs lifter, stores fresh IR artifacts, invokes verifier using manifest entries
- `scripts/rewrite/verify.ps1` — checks lifted output patterns/results from manifest entries and rejects non-skipped samples with empty `patterns` arrays
- `scripts/rewrite/manifest_validation.ps1` — shared strict manifest validator used by both `run.ps1` and `verify.ps1`
- `scripts/rewrite/run.cmd` — one-command Windows entrypoint
- `scripts/rewrite/run_microtests.cmd` — runs `rewrite_microtests.exe` (in-process instruction-byte tests from `lifter/test/TestInstructions.cpp`); builds lazily only when the executable is missing, supports `--build` to force rebuild and `--no-build` to require prebuilt binaries
- `scripts/rewrite/collect_instruction_tests.cmd` — reports handler coverage against `lifter/semantics/x86_64_opcodes.x` using oracle vector metadata (`handler` field) to track missing instruction tests
- `scripts/rewrite/generate_oracle_vectors.cmd` — regenerates `lifter/test/test_vectors/oracle_vectors.json` from seed vectors using oracle providers (currently Unicorn)
- `scripts/rewrite/oracle_seed_vectors.json` — seed cases with instruction bytes, initial state, and tracked outputs for oracle generation
- `scripts/rewrite/build_full_handler_seed.cmd` — builds `oracle_seed_full_handlers.json` (base semantic vectors + auto-discovered smoke vectors for missing handlers)
- `scripts/rewrite/build_full_handler_seed.py` — Capstone-based opcode discovery that fills missing handlers and marks known-crashing handlers as `skip`
- `scripts/rewrite/run_all_handlers.cmd` — generates full-handler seed/vectors and executes `rewrite_microtests.exe` across the full suite
- `scripts/rewrite/generate_flag_stress_vectors.cmd` — builds `lifter/test/test_vectors/oracle_vectors_flagstress.json` with multiple strict flag-oracle cases per flag-writing handler
- `scripts/rewrite/generate_flag_stress_vectors.py` — derives flag-writing handlers from `lifter/semantics/Semantics.ipp`, generates deterministic initial states, and computes expected flags via Unicorn
- `scripts/rewrite/run_flagstress.cmd` — one-command strict flag suite runner (auto-generates flag-stress vectors and executes microtests with strict flag assertions)
- `run.ps1` validates that `instruction_microtests.json` covers every `testcases/rewrite_smoke/*` source file
- `scripts/rewrite/check_semantic.py` — runtime semantic regression for all lifted samples; reads `semantic` cases from the manifest, generates lli-executable wrappers, and verifies return values across all declared inputs (33 samples, 177 test cases)

Helper build scripts for local development are in:

- `scripts/dev/configure_iced.cmd` — CMake configure (Ninja + clang-cl, auto-detects MSVC headers/libs)
- `scripts/dev/build_iced.cmd` — incremental `cmake --build` for iced backend
- `scripts/dev/configure_zydis.cmd` — CMake configure for Zydis-only lane
- `scripts/dev/build_zydis.cmd` — incremental `cmake --build` for Zydis backend

These scripts do **not** invoke `VsDevCmd.bat`. `clang-cl` discovers MSVC include/lib paths on its own, and CMake/Ninja bakes all resolved paths into `build.ninja` at configure time. This avoids loading the full VS Developer Environment (CLR, MSBuild, Roslyn) and saves ~200-400 MB of RAM per invocation.

### Build parallelism

All build scripts default to 4 parallel jobs. Override with `MERGEN_BUILD_JOBS`:

```bat
set MERGEN_BUILD_JOBS=2    &rem low-memory machines
set MERGEN_BUILD_JOBS=8    &rem fast builds on large machines
```

`run_microtests.cmd` regenerates oracle vectors by default, then runs `rewrite_microtests.exe`. It forwards optional args as name filters (example: `run_microtests.cmd xor`).
Use `run_microtests.cmd --check-flags <filter>` to enforce oracle flag comparisons (strict mode, expected to fail until flag semantics are fixed).
Use `run_microtests.cmd --build <filter>` to force rebuilding `rewrite_microtests.exe`, or `run_microtests.cmd --no-build <filter>` to skip any build step.
Set `SKIP_ORACLE_GENERATION=1` to reuse a pre-generated oracle file. Set `MERGEN_TEST_VECTORS=<path>` to point tests at a custom oracle JSON file.
Use `run_all_handlers.cmd` to exercise full handler coverage smoke tests. It writes `lifter/test/test_vectors/oracle_vectors_full_handlers.json` and then runs microtests against it through `run_microtests.cmd` (which now builds lazily).
Oracle vector JSON fixtures are deterministic by design; regenerating them should only change tracked files when the underlying cases change, not because of wall-clock metadata.
Full-handler vectors are expected to execute end-to-end (no default `skip: true` crash exclusions).
Use `run_flagstress.cmd` (or `python test.py flags`) for broad strict-flag validation across all handlers that explicitly write flags.
Use `python test.py semantic` to run runtime semantic regression for all samples (accepts `--filter` to narrow scope and `--input-ir` to override the IR file for a single sample).

## Output location

By default, regression artifacts are written to a sibling folder outside the repository:

- `../rewrite-regression-work/`

Artifacts include:
- `lifter/test/test_vectors/oracle_vectors_flagstress.json` (generated strict-flag stress suite)

- compiled sample binaries/maps/objects for every manifest entry
- `ir_outputs/*.ll` and `ir_outputs/*_no_opts.ll` (replaced on each run after stale `.ll` cleanup)
- `ir_outputs/*_semantic.ll` (generated by `check_semantic.py` for lli execution)

- `lifter/test/test_vectors/oracle_vectors_full_handlers.json` (generated by `run_all_handlers.cmd`)
## Running the baseline gate

From repository root:

```bat
scripts\rewrite\run.cmd
```

CI requires a pinned sample-build compiler via `CLANG_CL_EXE`, `CMAKE_C_COMPILER`, or `LLVM_DIR`. For local runs, set `CLANG_CL_EXE=C:\Program Files\LLVM\bin\clang-cl.exe` when you want `scripts\rewrite\run.cmd` or `python test.py quick` to use the same sample-build compiler resolution as CI instead of relying on fallback discovery.

Optional custom output directory:

```bat
scripts\rewrite\run.cmd "C:\path\to\custom-workdir"
```

## Running failure-contract checks

From repository root:

```bat
python test.py negative
```

This gate asserts explicit failure behavior for malformed manifests/vectors, vectors paths outside the repository root, and invalid lifter invocation inputs.

## Pass criteria

`run.ps1` enforces manifest/source parity before lifting (every source in `testcases/rewrite_smoke/` has exactly one manifest entry: no missing, no extra), validates sample names/symbols/skip types, and rejects path-traversal sample names.

`run.ps1` also clears top-level `output.ll` / `output_no_opts.ll` before each lift and fails if lifter does not regenerate both files, preventing stale-artifact false passes.

`verify.ps1` enforces, for each non-skipped manifest entry:

- `patterns` is non-empty (empty arrays are treated as configuration errors)
- every pattern descriptor is valid (`string` with non-empty content, or `{ "line_all": [non-empty string tokens...] }`)
- lifted IR file exists at `ir_outputs/<sample>.ll`
- every expected pattern declared in `instruction_microtests.json` is present in that IR output
A rewrite change is not acceptable if this baseline fails.
`python test.py quick` and `python test.py all` additionally run runtime semantic validation for **all** samples after baseline lifting, executing each lifted IR module via LLVM `lli` and asserting correct return values across all declared input vectors. This prevents regressions where lifted IR looks structurally correct (passes pattern checks) but computes wrong results.
For larger control-flow, semantics, or inlining changes, also run `python test.py vmp` to make sure the stable local VMProtect targets still lift without hard regression.


## Runtime semantic regression

Every non-skipped sample in the manifest may declare a `semantic` field: an array of `{inputs, expected, label}` objects. The `check_semantic.py` runner:

1. Reads the optimized lifted IR from `ir_outputs/<sample>.ll`
2. Strips dead stores to unmapped binary addresses (`inttoptr`)
3. Renames `@main` to `@lifted_<sample>` and generates an `@semantic_main` wrapper
4. Runs the wrapper via `lli --entry-function=semantic_main`
5. Reports per-case pass/fail with input/expected detail on failure

Samples without a `semantic` field are not tested. The `semantic` field is optional but recommended for every sample with a deterministic expected return value.

### Coverage summary

Current active quick-gate semantic coverage is **33 samples / 177 cases** on CI and local pinned-toolchain runs.

Notable current state:
- `dummy_vm_loop`, `bytecode_vm_loop`, and `stack_vm_loop` are active VM-shaped control-flow samples.
- `calc_sum_to_n`, `calc_fib`, and `calc_sum_array` are active again under the current safe path.
- `calc_cout` is active again after SSE2 `PUNPCKLQDQ` support landed; the manifest currently has zero `ci_skip` entries.

## Call-boundary ABI framework

The lifter includes a cross-ABI call-boundary contract (`AbiCallContract.hpp`) that models:

- **ABI kind**: x64 MSVC, x86 cdecl/stdcall/fastcall, unknown
- **Call model mode**: `strict` (default) or `compat` (diagnostic fallback)
- **Call effects**: argument registers, return registers, volatile clobber set, stack cleanup convention, memory effect assumption

### Dual-mode behavior

| Mode | Return value | Volatile clobber | Memory effect | Arg list |
|------|-------------|-----------------|---------------|----------|
| `compat` | RAX = call result | None (all regs preserved) | Preserve | All 16 GPRs + memory ptr |
| `strict` | RAX = call result | RAX, RCX, RDX, R8-R11 set to undef | MayReadWrite | ABI arg regs only + memory ptr |

### Configuration

- `lifterClassBase::callModelMode` controls the mode (default: `Strict`)
- `lifterClassBase::defaultAbi` overrides auto-detection (default: `Unknown`, inferred from file mode)
- Diagnostics printed to stdout with `[call-abi]` prefix at each call site

### Verification expectations

- **Strict mode is the default.** It is ABI-correct: volatile registers (RAX, RCX, RDX, R8-R11) become `undef` after non-inlineable calls, non-volatile registers (RBX, RSI, RDI, RBP, R12-R15) survive. This is safe for all compiler-generated code because the compiler saves volatile values to non-volatile registers before calls. The lifter operates in SSA, so values computed before the call are bound and survive regardless of register clobber.
- **Compat mode** is available as opt-in fallback (`CallModelMode::Compat`). It preserves all registers across calls. Use for diagnostic comparison only.
- **Inlineable calls are unaffected.** The Unflatten path follows the call target and returns; no CreateCall is emitted, no ABI effects are applied. This covers all VMP/Themida internal calls.
- `ret imm16` diagnostics note callee-cleanup detection.
- The `parseArgs(nullptr)` path no longer has a duplicated RDI register (was a pre-existing bug).