# Autoresearch

## Goal
- Advance the Themida internal `0x140001000` frontier beyond the validated `35 attempted / 1565 instructions` baseline without reintroducing the broad generalized-loop memory regressions documented in `themidahandoff.md`.

## Benchmark
- command: bash autoresearch.sh
- primary metric: instructions_lifted
- metric unit: instructions
- direction: higher
- secondary metrics: blocks_attempted, blocks_completed, total_ms

## Files in Scope
- lifter/memory/GEPTracker.ipp
- lifter/core/LifterClass_Concolic.hpp
- lifter/core/LifterClass.hpp
- lifter/core/LifterClass_Symbolic.hpp
- lifter/test/Tester.hpp
- lifter/test/test_vectors/oracle_vectors.json
- lifter/semantics/Semantics_Bitwise.ipp
- lifter/semantics/Semantics_Arithmetic.ipp
- lifter/semantics/OperandUtils.ipp
- lifter/disasm/CommonDisassembler.hpp
- lifter/disasm/IcedDisassembler.hpp
- lifter/analysis/PathSolver.ipp

## Off Limits
- C:/Users/Yusuf/Desktop/mergenrewrite/testthemida/example2-virt.bin
- autoresearch.program.md
- autoresearch.sh
- themidahandoff.md

## Constraints
- Keep the benchmark input, lifted entry address, and diagnostics mode fixed: `../testthemida/example2-virt.bin`, `0x140001000`, `MERGEN_DIAG_LIFT_PROGRESS=1`.
- Benchmark the iced lane binary at `build_iced/lifter.exe`; rebuild incrementally before each run with the repo-provided Windows build script.
- Preserve the current correctness envelope inside the benchmark harness itself: benchmark runs must keep `instructions_unsupported == 0`, `summary.warning == 0`, and `summary.error == 0`, and fail immediately if any of those regress.
- Do not retry the handoff’s ruled-out broad strategies: generic non-local memory PHIs, raw control-slot buffer merges, generic possible-values PHI enumeration, or naive side maps.
- Prefer the narrowest representation that expresses control-derived field loads only in generalized-loop restore mode, starting with `control + 0xC` before broadening to `+0xA` or `+0x6`.

## Preflight
- Prerequisites: configured iced build tree exists and `build_iced/lifter.exe` is runnable from repo root; Python is available through the Windows `py -3` launcher for metric extraction.
- One-time setup: none beyond the existing `build_iced/` tree and this benchmark harness.
- Comparability invariant: every run must execute the same command path (`bash autoresearch.sh`), rebuild from the current source tree with the same lane, and lift the same fixed Themida sample and entrypoint while extracting metrics from the newly written `output_diagnostics.json`.

## Baseline
- metric: pending
- notes: pending first logged run

## Current best
- metric: pending
- why it won: pending first logged run

## What's Been Tried
- experiment: broad generalized-loop memory PHIs in tracked buffer
- lesson: advanced Themida but regressed rewrite quick; wrong abstraction.
- experiment: merge only the raw control cursor slot (`0x14004DD19`)
- lesson: reproduced the same progress/regression pattern, proving the lever is downstream derived-field use, not the slot itself.
- experiment: direct raw control-slot load override
- lesson: no improvement; exact slot loads are not the missing representation.
- experiment: side-map or generic possible-values broadening
- lesson: either destabilized execution or failed to move the frontier; keep the next change surgical.
