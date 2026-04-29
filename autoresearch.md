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
- metric:
- notes:

## Current best
- metric:
- why it won:

## What's Been Tried
- experiment: stale README / loop-handling notes investigated
- lesson: current tree already passes the Themida equivalence gate; the bug is in docs, not lifting.
