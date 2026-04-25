# Autoresearch

## Goal
- Populate more rewrite-smoke test cases that exercise VM-shaped dispatch with
  real loops, including custom toy VMs (register machines, nested loops in PC
  state, conditional branches inside VM loop bodies). Each new sample must be
  fully wired into the manifest with a symbol, IR pattern set, and at least
  six semantic test cases covering edge inputs.

## Benchmark
- command: bash autoresearch.sh
- primary metric: vm_sample_count
- metric unit: count
- direction: higher
- secondary metrics: total_semantic_cases, manifest_samples

## Files in Scope
- testcases/rewrite_smoke/
- scripts/rewrite/instruction_microtests.json

## Off Limits
- lifter/
- scripts/dev/
- scripts/rewrite/run.cmd
- scripts/rewrite/run.ps1
- scripts/rewrite/verify.ps1
- scripts/rewrite/build_samples.cmd
- scripts/rewrite/manifest_validation.ps1
- scripts/rewrite/check_semantic.py
- test.py

## Constraints
- Every file in `testcases/rewrite_smoke/` MUST have exactly one matching
  manifest entry in `scripts/rewrite/instruction_microtests.json` (manifest
  validation enforces this on `python test.py baseline`).
- Manifest entries MUST include `name`, `symbol`, `patterns` (non-empty),
  and `semantic` with concrete inputs and expected return values.
- New VM samples MUST keep their dispatcher in `__declspec(noinline)` and
  use symbolic input-derived loop bounds so the lifter cannot constant-fold
  the loop away.
- Samples MUST be lli-executable: avoid bytecode-array memory loads outside
  the function stack and avoid platform-specific intrinsics.
- DO NOT modify the lifter, build pipeline, or verification scripts.

## Preflight
- `clang-cl` and `nasm` resolution is handled by `scripts/rewrite/build_samples.cmd`.
- Full lifter regression requires `python test.py baseline`, which wipes
  `build_iced/`. Treat that as expensive and run only when validating a
  batch of new samples end-to-end.
- The autoresearch metric is cheap (manifest stats only); end-to-end
  lifter/lli verification is a separate, manual gate.

## Comparability invariant
- Metric is computed by parsing `scripts/rewrite/instruction_microtests.json`
  with a fixed Python snippet inside `autoresearch.sh`. Do not change the
  parser or the manifest schema between runs without re-initializing the
  segment.

## Baseline
- metric:
- notes:

## Current best
- metric:
- why it won:

## What's Been Tried
- experiment: vm_callret_loop with explicit return-PC stack (rstack[rsp])
  lesson: dispatcher reads next pc from a stack array; lifter cannot generalize the indirect dispatch and trips diagnostic 503 (basic-block budget exceeded, ~4087 blocks). Sample removed; revisit when loop generalization handles stack-indexed pc.
- experiment: vm_subroutine_loop with single-int rpc slot (one-deep call/ret)
  lesson: even a single non-indexed `pc = rpc` indirect dispatch crashes the lifter (access violation, exit 0xC0000005) when invoked through PowerShell. The ret-to-stack-loaded-pc pattern is fundamentally unsupported regardless of stack depth. Removed.
- experiment: vm_bubblesort_loop with adjacent compare-and-swap on a stack array
  lesson: even a single bubble pass (loop body conditionally writes TWO indexed stack-array slots) trips diagnostic 503 (BB budget exceeded). The lifter enumerates the swap-vs-no-swap path across every iteration. Comparison-driven update of a single accumulator (vm_minarray_loop) is fine; two-slot conditional writes inside a loop are not. Sample removed.
- experiment: vm_switch_dispatch_loop using `switch` for dispatch
  lesson: lifter collapsed the switch-dispatched VM to a constant -1 return; same class of limitation. Removed.
- experiment: end-to-end rewrite regression via run_experiment
  lesson: harness env sets CI=1 and LLVM_DIR points at an install without bundled clang-cl, so build_samples.cmd refuses host fallback. Must pin CLANG_CL_EXE explicitly.
- experiment: speculative IR patterns vs lifter-observed shapes
  lesson: 13/18 first-pass VM patterns missed because the lifter heavily compresses dispatchers (if-else -> switch i32, fixed-trip loops unrolled or recognized as intrinsics like llvm.bitreverse.i8, triangular sums closed-form-solved into mul i33 + lshr i33). Patterns must be derived from lifted IR, not from source-level shape.
- experiment: lli semantic check found undef for empty-loop inputs (limit=0) in branchy/collatz
  lesson: lifter pseudo-stack promotion drops the entry-block init when the same slot is also written inside a dispatcher state. Fix is the dual_counter pattern: keep an explicit init dispatcher state on the entry-to-halt path. branchy needed `i=0; count=0;` inside BV_LOAD_LIMIT to thread `[ 0, %entry ]` through the loop phi instead of `[ undef, %entry ]`.
