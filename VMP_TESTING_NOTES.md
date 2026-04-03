# VMP Testing Notes

## Purpose
Preserve the concrete lessons from local VMP testing so future sessions do not repeat the same false starts.

## Verified local targets
- VMP 3.8.x-style samples:
  - `simple/protected381/simple_target_one_vm.vmp38.exe`
  - `simple/protected381/simple_target.vmp.exe`
- Older protected sample:
  - `simple/protected/simple_target_protected.vmp.exe`

## Verified addresses and paths
### Direct protected-function path (older protected sample)
- Target address used: `0x14009E2E1`
- Verified with Unicorn/Capstone:
  - `SCASD`
  - `CLC`
  - `INC ECX`
  - `INT 2`
- Without an interrupt/exception handler, execution stops at `INT 2`.
- Therefore naive fallthrough semantics after `INT 2` are wrong for this protected path.

### Real PE entrypoint path (older protected sample)
- PE entrypoint: `0x140011267`
- Early bounded startup trace clearly reaches `REP STOSB` and CRT/runtime setup.
- First concretely resolved startup import on that path:
  - `KERNEL32!GetSystemTimeAsFileTime`
  - IAT slot `0x140020098`
- In bounded entrypoint emulation, SCAS/INT were not reached before startup/runtime behavior took over.

## Important codeflow warning
Do not assume the intended VMP 3.6 continuation matches ordinary architectural fallthrough.

Evidence:
- `simple/research/vmp36/vmp36_dispatch_log.txt` shows the expected next continuation after cycle 0 is `0x14009E2E6`.
- Ordinary execution after `INT 2` would continue at `0x14009E2E7` only if an interrupt handler resumed execution, and even that still does not explain the logged `0x14009E2E6` continuation.

Practical conclusion:
- The older protected sample appears to rely on exception/dispatcher-mediated control flow.
- Treat `simple/research/vmp36/vmp36_dispatch_log.txt` as stronger evidence of intended protected flow than naive CPU fallthrough after `INT 2`.

## Implementation status from this session
- Implemented non-prefixed SCAS family support:
  - `SCASB`
  - `SCASW`
  - `SCASD`
  - `SCASQ`
- `REP`/`REPE`/`REPNE`-prefixed SCAS forms are still rejected as `not_implemented` until the lifter can model repeated scan termination correctly.
- After that change, the older protected direct path gets past `SCASD` and then stops at `INT`.
- That does **not** mean plain `INT` semantics will recover the real protected flow.

## Performance lessons
For the runnable protected381 samples, the main speed work is on the lifting path, not decoder choice.

Profiler findings:
- `lift_semantics` dominates lift time.
- Inside semantics, the hottest proven helper was `folderBinOps`.
- A conservative `folderBinOps` fast-path optimization produced a real improvement.
- A `GetEffectiveAddress()` tweak did **not** produce a defensible win and was reverted.

## Recommended future workflow
### If the goal is performance
Use `simple/protected381/*`.
- These are the best local VMP-style performance targets.
- Continue profiling semantics/memory/folder helpers there.
- For large control-flow/semantics/inlining changes, run `python test.py vmp` from repo root. That command now fails required targets on diagnostics errors **or** `blocks_completed == 0`, while still reporting the older VMP 3.6 sample as best-effort only.
- The current safe configuration keeps loop-header generalization disabled and relies on a higher basic-block budget for the stable 3.8.x samples.

### If the goal is older protected/VMP 3.6 support
Use `simple/protected/simple_target_protected.vmp.exe`, but do not treat it as a normal instruction-semantics-only problem.

Recommended order:
1. Consult `simple/research/vmp36/VMP36_ANALYSIS.md`
2. Consult `simple/research/vmp36/vmp36_dispatch_log.txt`
3. Avoid assuming plain fallthrough after `INT 2`
4. Treat dispatcher/exception behavior as the likely real blocker

## Related files
- `simple/research/vmp36/VMP36_ANALYSIS.md`
- `simple/research/vmp36/vmp36_dispatch_log.txt`
- `simple/research/vmp36/trace_vmp36*.py`
