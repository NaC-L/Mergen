# Autoresearch

## Goal
- Sync Themida-facing docs and manifest notes with the current passing behavior of `example2-virt.bin`.

## Benchmark
- command: bash autoresearch.sh
- primary metric: themida_pass_count
- metric unit: count
- direction: higher
- secondary metrics: missing_required_imports

## Files in Scope
- README.md
- docs/LOOP_HANDLING.md
- scripts/rewrite/themida_samples.json
- autoresearch.sh

## Off Limits
- lifter/
- build_iced/
- testthemida/
- test.py
- scripts/dev/

## Constraints
- Do not change lifter behavior in this segment.
- Only update stale documentation / manifest commentary.
- Verification must use the existing `python test.py themida` gate.

## Preflight
- `build_iced/lifter.exe` already exists in this workspace.
- The Themida sample binaries live in `../testthemida/`.

## Comparability invariant
- `autoresearch.sh` must keep using `python test.py themida` and the same sample set.

## Baseline
- metric: 1
- notes: `python test.py themida` passes for the single tracked sample (`example2`).

## Current best
- metric: 1
- why it won: The code path was already correct; syncing stale README / loop-handling / manifest commentary removed the visible mismatch without changing lifter behavior. The benchmark harness is kept in its simpler tee-based form because the more complex single-path PowerShell rewrite did not improve capture or metrics.

## What's Been Tried
- experiment: stale README / loop-handling notes investigated
- lesson: current tree already passes the Themida equivalence gate; the bug is in docs, not lifting.
- experiment: direct `run_experiment` capture probe via `python.exe test.py themida`
- lesson: on this workstation, `run_experiment` leaves `benchmark.log` empty even when the command succeeds, so parsed metrics stay null. Keep manual metric logging for this segment instead of treating `autoresearch.sh` as the cause.
- experiment: alternate wrapper probe via `cmd /c bash autoresearch.sh`
- lesson: changing the command form does not fix capture; the command succeeds under direct shell execution but still fails with exit 127 and an empty benchmark log under `run_experiment`.
- experiment: PowerShell wrapper probe via `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "python.exe test.py themida"`
- lesson: a third launcher shape still produces an empty benchmark log with null parsed metrics under `run_experiment`, so the runner limitation is wrapper-independent on this workstation.
- experiment: cmd Python probe via `cmd /c python.exe test.py themida`
- lesson: cmd-based direct Python launch also fails under `run_experiment` while succeeding in the shell, so no launcher variant within scope is fixing benchmark capture.
- experiment: simplified single-path `autoresearch.sh` using one PowerShell invocation
- lesson: even after collapsing the harness to a single launcher and metric-emission path, direct shell output works but `run_experiment` still records an empty benchmark log with null parsed metrics. The remaining fault is outside repo-scoped harness logic.
- experiment: restore the simpler tee-based `autoresearch.sh` wrapper
- lesson: equal metric with less harness complexity is the better kept state. Capture still fails under `run_experiment`, but the extra PowerShell-only rewrite provided no benefit.
- experiment: segment exhaustion check
- lesson: with `themida_pass_count` already at 1 for the only tracked sample, lifter/test/sample changes off-limits, and runner capture failures proven across direct, cmd, bash, and PowerShell launch shapes, there is no remaining in-scope repo change likely to improve the metric or produce a better kept state.
