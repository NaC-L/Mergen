# Mergen Reviewer Rules

These rules are for PR review of this repository. They are intentionally strict and optimized for catching semantic regressions, flaky test artifacts, and false-green rewrite gates.

## 1) Review Contract

1. Review only the files in the PR scope. No drive-by changes.
2. Always inspect the real diff first (`git diff` / `git show`) before reading full files.
3. For every non-trivial changed symbol, review its direct consumers before concluding correctness.
4. Prefer correctness over style. Do not block on formatting-only nits.
5. Do not accept compatibility shims for refactors unless explicitly requested; prefer full cutover.

## 2) Required Workflow

1. **Map the change**
   - `git diff --name-status <base>...<head>`
2. **Review by subsystem bucket** (core, disasm/semantics, rewrite scripts, vectors, build scripts, docs)
3. **Inspect each bucket deeply**
   - `git diff -- <files>`
   - read surrounding context for changed hunks
4. **Run targeted verification** (see matrix below)
5. **Report findings with evidence**
   - file path + line range
   - failure condition
   - user-visible/system-visible impact
   - concrete fix direction

## 3) Severity Rubric

- **P0**: silent miscompile/mislift, memory corruption, security-sensitive path traversal/execution bug.
- **P1**: incorrect semantics/results, wrong oracle outcomes, false-green gate, broken build lane.
- **P2**: deterministic/reliability regressions, incorrect fallback behavior, brittle tooling contracts.
- **P3**: docs drift, maintainability concerns without immediate correctness impact.

Default: request changes for any P0/P1. P2 is usually request changes unless clearly non-blocking.

## 4) Repo-Specific Invariants (Block if violated)

### 4.1 Backend selection (CMake/dev scripts)

- Exactly one backend state should be active (`ICED_FOUND` xor `ICED_NOT_FOUND`).
- Do not regress explicit toolchain overrides (e.g., `CARGO_EXECUTABLE`).
- Reconfigure scripts must prevent stale cache contamination between iced/zydis lanes.

### 4.2 Runtime image context and PE mapping

- Runtime address validation must reject invalid ranges but preserve valid header-backed RVAs.
- RVA->file offset mapping must distinguish unmapped virtual tails vs valid file-backed bytes.
- Errors must be explicit; avoid silent fallback to plausible-but-wrong context.

### 4.3 Cross-language operand model consistency

- `OperandType` ordering/meaning must stay consistent across:
  - `icpped_rust/src/lib.rs`
  - `lifter/disasm/CommonDisassembler.hpp`
  - downstream semantics helpers
- New register widths (e.g., 128-bit XMM) must be wired through conversion + size helpers + operand readers/writers.

### 4.4 Semantics/opcode table coherence

- New opcode entries in `lifter/semantics/x86_64_opcodes.x` must have a concrete handler implementation.
- Handler operand-form restrictions must match intent (e.g., XMM-only SSE2 integer ops).
- Flag behavior must match instruction semantics where flags are expected/validated.

### 4.5 Oracle vectors and test artifacts

- Oracle schema/version fields must remain valid.
- `skip` fields must be boolean where schema expects boolean.
- Case names should be unique and stable.
- XMM register snapshots must be fixed-width 128-bit hex (32 hex digits after `0x`).
- Do not accept timestamp-only churn that hides inconsistent case payloads.

### 4.6 Rewrite manifest safety

- Manifest must validate as strict JSON object with `samples`.
- Sample names must reject traversal/path separators.
- `run.ps1` must enforce source↔manifest parity (no missing/extra/duplicate sample names).
- `verify.ps1` pattern descriptors must reject malformed entries and empty required content.

## 5) Verification Matrix (Run what matches changed files)

| Changed area | Minimum verification |
|---|---|
| `lifter/core/**`, `lifter/disasm/**`, `lifter/semantics/**`, `lifter/test/**` | `python test.py micro --check-flags` (add focused filters if needed) |
| `scripts/rewrite/**` (validation/oracle/verify/run) | `python test.py negative` and `python test.py baseline` |
| opcode coverage/vector plumbing (`x86_64_opcodes.x`, coverage scripts, vector manifests) | `python test.py coverage --full` and `python test.py report --json` |
| `cmake/**`, `scripts/dev/**` | affected lane configure+build (`scripts\dev\configure_iced.cmd` + `build_iced.cmd`, and/or `configure_zydis.cmd` + `build_zydis.cmd`) |
| docs-only | consistency review; no runtime gate required |

If an expected command cannot run (missing env/toolchain), report the exact blocker and do not claim verification passed.

## 6) Finding Quality Bar

A finding is valid only if it includes all of:

1. **Where**: exact file and line(s)
2. **When it breaks**: concrete condition/input
3. **Why it matters**: correctness/reliability/security impact
4. **How to fix**: direct, minimal remediation path

Reject vague findings like “might break” without a concrete failure path.

## 7) Review Output Template

```text
Verdict: approve | comment | request_changes

Summary:
- <1-3 lines>

Findings:
- [P1] <title>
  - File: <path>:<line-range>
  - Failure: <specific scenario>
  - Impact: <observable consequence>
  - Fix: <actionable change>

Verification run:
- <command>: PASS/FAIL/BLOCKED
- <command>: PASS/FAIL/BLOCKED
```

## 8) Quick Commands

```bat
git diff --name-status main...<branch>
git diff -- main...<branch> -- <path>
python test.py negative
python test.py baseline
python test.py micro --check-flags
python test.py coverage --full
python test.py report --json
```

## 9) Review Automation Shortcuts

Use these helpers for faster, repeatable review setup before manual deep-dive:

```bat
python scripts/review/risk_map.py --base main --head HEAD
python scripts/review/shard_pr.py --base main --head HEAD
python scripts/review/verify_plan.py --base main --head HEAD
python scripts/review/verify_plan.py --base main --head HEAD --run
python scripts/review/invariant_guard.py --base main --head HEAD
```

For local iteration without a branch diff, pass explicit files:

```bat
python scripts/review/risk_map.py --paths <file1> <file2> ...
python scripts/review/verify_plan.py --paths <file1> <file2> ... --run
```

Use this document as the default reviewer policy unless a PR explicitly narrows scope.