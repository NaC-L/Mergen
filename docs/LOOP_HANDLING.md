# Loop Handling

This file documents how the lifter currently recognizes loops, how it switches a recognized loop into "generalized" lifting mode, and how the generalized state is consumed by downstream value tracking. It also lists the load-bearing hardcoded addresses, the gating contexts, and the known limitations so the next session can change loop behavior without re-excavating the code.

For build/test workflow use `docs/BUILDING.md` and `docs/REWRITE_BASELINE.md`. For the support matrix use `docs/SCOPE.md`. For the pipeline order around loop lifting use `ARCHITECTURE.md`.

## Phases

Loop handling is a sequence of three phases on the same basic block:

| Phase | What it does | Where |
|---|---|---|
| Detect | Recognize that a backward jump target is a real loop header (not an acyclic backward branch) | `isStructuredLoopHeaderShape` + `canGeneralizeStructuredLoopHeader` in `lifter/core/LifterClass.hpp` |
| Generalize | Switch the lifter from concrete per-path execution to a phi-driven "loop mode" at the header | `branch_backup`, `load_generalized_backup`, `record_generalized_loop_backedge` in `lifter/core/LifterClass_Concolic.hpp` |
| Consume | Re-route specific load / register reads through canonical/backedge phi values during loop-mode lifting | `retrieve_generalized_loop_*` family in `lifter/core/LifterClass_Concolic.hpp` |

## Detection

`isStructuredLoopHeaderShape(BasicBlock*)` walks the block chain starting at the candidate header and accepts on the first conditional branch it reaches, with these constraints:

- Maximum walk depth: 8 hops.
- The header itself may have up to 2 predecessors; deeper hops in the chain may have only 1 predecessor each.
- Each hop must terminate with a `BranchInst`.
- A non-conditional unconditional `br` with a single successor is allowed (trampoline relaxation), but a multi-successor non-branch terminator rejects.
- An empty block on any hop rejects.
- A cycle in the walk rejects.

Trampoline relaxation: when the entry block is a single unconditional `br` and a deeper hop has not yet been fully terminated (mid-lift), the chain is still accepted so the header can be latched. The actual loop-vs-acyclic decision is made by `blockCanReach` and `visitedAddresses` checks downstream.

`canGeneralizeStructuredLoopHeader(addr)` then applies the operational guards in this order:

1. `getControlFlow() == ControlFlow::Unflatten` — feature-gate.
2. `currentPathSolveAllowsStructuredLoopGeneralization()` (or the resolved-target widening) — see [Path-solve context gating](#path-solve-context-gating).
3. `addr <= blockInfo.block_address` — only backward targets.
4. `visitedAddresses.contains(addr)` — header must already have been lifted at least once.
5. Not already in `pendingLoopGeneralizationAddresses`.
6. Not already in `generalizedLoopAddresses`.
7. `addrToBB[addr]` exists and is non-empty.
8. `isStructuredLoopHeaderShape(it->second)`.
9. `blockCanReach(header, currentBlock)` — confirms an actual cycle.

All guards must pass; any reject is logged via diagnostic output gated on `liftProgressDiagEnabled` (`MERGEN_DIAG_LIFT_PROGRESS=1`).

### Path-solve context gating

`currentPathSolveContext` distinguishes how the lifter reached the current point:

| Context | Generalization allowed? |
|---|---|
| `ConditionalBranch` | yes |
| `DirectJump` | yes |
| `IndirectJump` | only via the resolved-target widening (`...ForResolvedTarget`) |
| `Ret` | no |

The `IndirectJump` widening exists because once `solvePath` has pinned an indirect jump to a concrete address, that target is no longer speculative and a backward edge is a legitimate loop. Ret-path contexts have their own lifecycle and are deliberately excluded from generalization.

## Generalized loop state

When generalization fires, the lifter re-enters the header in "loop mode." The state lives in `lifter/core/LifterClass_Concolic.hpp`:

```cpp
struct GeneralizedLoopControlFieldState {
  bool valid = false;
  llvm::BasicBlock* headerBlock = nullptr;
  llvm::BasicBlock* canonicalSource = nullptr;
  llvm::BasicBlock* backedgeSource = nullptr;
  uint64_t canonicalControl = 0;
  uint64_t backedgeControl = 0;
  llvm::DenseMap<uint64_t, ValueByteReference> canonicalBuffer;
  llvm::DenseMap<uint64_t, ValueByteReference> backedgeBuffer;
} activeGeneralizedLoopControlFieldState;

llvm::DenseMap<llvm::BasicBlock*, GeneralizedLoopControlFieldState>
    generalizedLoopControlFieldStates;
```

`activeGeneralizedLoopControlFieldState` tracks the state for the loop currently being lifted. `generalizedLoopControlFieldStates` is the per-header archive used after promotion so a later re-entry can rebuild the state.

Two related stores hold raw register/flag phi nodes per header:

- `generalizedLoopRegisterPhis: BB -> array<PHINode*, REGISTER_COUNT>`
- `generalizedLoopFlagPhis: BB -> array<PHINode*, FLAGS_END>`

State transitions:

| Event | What changes |
|---|---|
| `branch_backup(bb, generalized=false)` | Snapshots current registers/flags/buffer/cache/assumptions/counter into `BBbackup[bb]`. |
| `branch_backup(bb, generalized=true)` | Same snapshot stored into `generalizedLoopBackedgeBackup[bb]`; `BBbackup[bb]` only set if absent. |
| `load_backup(bb)` | Restores `BBbackup[bb]`, clears `activeGeneralizedLoopLocalBuffer`. |
| `load_generalized_backup(bb)` | Builds `make_generalized_loop_backup(bb)` and restores it; populates `activeGeneralizedLoopControlFieldState` from the canonical/backedge snapshots. |
| `record_generalized_loop_backedge(bb)` | Promotes the loop: copies `activeGeneralizedLoopControlFieldState` into the per-header archive, marks the address generalized. |

## Phi construction at the header

`make_generalized_loop_backup(bb, canonical, backedge)` calls `mergeValue` for every register and flag slot:

```cpp
auto mergeValue = [&](Value* canonicalValue, Value* backedgeValue,
                      const char* name, PHINode*& phiOut,
                      bool widenFirstBackedge) -> Value* {
  if (!canonicalValue || !backedgeValue ||
      types differ || canonical == backedge) {
    return backedgeValue;          // no phi needed
  }
  auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(), 2, name);
  phi->addIncoming(canonicalValue, canonicalSource);
  phi->addIncoming(widenFirstBackedge
                       ? UndefValue::get(backedgeValue->getType())
                       : backedgeValue,
                   backedgeSource);
  phiOut = phi;
  return phi;
};
```

`widenFirstBackedge` controls whether the backedge incoming is `Undef` (allowing later folding to refine) or the concrete backedge value:

- Registers: `widenFirstBackedge = !shouldPreserveGeneralizedBackedgeRegisterIndex(i)`. RSP is preserved (passes the actual backedge value), every other GPR widens to `Undef`.
- Flags: always widen to `Undef`.

Preserving RSP through the first backedge prevents the stack pointer from being treated as "could be anything" inside the loop body.

## Consuming the state during loop-mode lifting

When the lifter is in loop mode (`currentBlockUsesGeneralizedLoopState() == true`) and the active state is valid, several read paths re-route through the state instead of the normal load/register pipeline. All are CRTP-dispatched in `lifter/core/LifterClass.hpp` and implemented in `lifter/core/LifterClass_Concolic.hpp`; symbolic-mode stubs in `lifter/core/LifterClass_Symbolic.hpp` return `nullptr` so symbolic analysis is unchanged.

| Helper | What it returns |
|---|---|
| `retrieve_generalized_loop_local_value(addr, bytes)` | Loop-local stack-buffer value if `activeGeneralizedLoopLocalBuffer` has it; else `nullptr` (caller falls back). |
| `retrieve_generalized_loop_control_field_value(loadOffset, bytes, orgLoad)` | Phi of canonical/backedge values for a load whose offset is `controlSlot + (Trunc/ZExt/SExt of) phi` with a recognized constant displacement. |
| `retrieve_generalized_loop_control_slot_value(addr, bytes)` | Phi of canonical/backedge control values when `addr == kThemidaControlCursorSlot`. |
| `retrieve_generalized_loop_target_slot_value(addr, bytes)` | Phi of canonical/backedge values for a recognized target slot. |
| `retrieve_generalized_loop_phi_address_value(load, bytes, orgLoad)` | Phi of loaded values when the load's address is a phi of two concrete addresses derived from canonical/backedge. |
| `retrieve_generalized_loop_local_phi_address_value(load, bytes, orgLoad)` | Same as above for loop-local stack-buffer addresses. |
| `resolveTargetedThemidaR9(value)` | At three hardcoded Themida instruction addresses, replaces R9 with `(canonicalControl + offset, backedgeControl + offset)` phi. See [Hardcoded reference-sample addresses](#hardcoded-reference-sample-addresses). |

`computePossibleValues` (in `lifter/memory/GEPTracker.ipp`) also has a `PHINode` case that unions every incoming's value set, so callers downstream of these phis get the full possible-value enumeration instead of an empty fallback.

## Hardcoded reference-sample addresses

A handful of constants in `lifter/core/LifterClass_Concolic.hpp` are tied to the reference Themida sample (`testthemida/example2-virt.bin @ 0x140001000`):

```cpp
static constexpr uint64_t kThemidaControlCursorSlot = 0x14004DD19ULL;
static constexpr uint64_t kThemidaLoopCarriedSlot   = 0x14004DC67ULL;
static constexpr std::array<uint64_t, 3> kSupportedGeneralizedControlFieldOffsets = {
    0x6ULL, 0xAULL, 0xCULL};
```

`resolveTargetedThemidaR9` adds three hardcoded `(instruction-address, control-offset)` pairs:

| Instruction address | Control offset | Verified hit count on reference sample |
|---|---|---|
| `0x140023671` | `0x0` | 3 |
| `0x14002368D` | `0xA` | 6 |
| `0x140023741` | `0xC` | 12 |

These pairs are load-bearing for the 2544-instruction Themida benchmark — removing them regresses the lifted output. They exist because the lifter's symbolic R9 value at those points has lost the controlCursor identity; the override re-injects the canonical/backedge phi directly.

Generalizing this away requires either (a) preserving the controlCursor identity through the upstream symbolic computation, (b) adding a tagging layer that marks values as "derived from controlCursor + const," or (c) a static-analysis pass that scans the function once and auto-derives the `(address, offset)` pairs. This is documented as known follow-up work, not a quick refactor.

The diagnostic prints scattered across `PathSolver.ipp`, `LifterClass.hpp`, `LifterClass_Concolic.hpp`, and `GEPTracker.ipp` that gate on specific Themida addresses (`0x1400237F9ULL`, `0x140023582-0x1400237FFULL`, etc.) only fire under `MERGEN_DIAG_LIFT_PROGRESS=1` and are session scaffolding for that sample. They produce no output for any other binary.

## Tests

Loop handling has roughly thirty microtests in `lifter/test/Tester.hpp`. The most relevant groups:

| Group | Coverage |
|---|---|
| `structured_loop_header_*` | Acceptance / rejection for conditional, jump-chain, acyclic-backward, non-conditional-terminator, multi-predecessor shapes. |
| `loop_generalization_*` | Per-context guards: conditional branch allowed, direct jump allowed, indirect jump blocked when unresolved / allowed when resolved, ret blocked. |
| `pending_generalized_loop_*` | Same guards in the `pendingLoopGeneralizationAddresses` lifecycle. |
| `generalized_loop_restore_*` | Backedge flag-state and register-state merging across `load_generalized_backup`. |
| `generalized_loop_*_creates_phi` | Each `retrieve_generalized_loop_*` helper produces the expected phi shape (control slot, control slot displacement, target slot, control field load, local phi address). |
| `targeted_themida_r9_override_produces_phi` | All three hardcoded `(address, offset)` pairs in `resolveTargetedThemidaR9`. |
| `compute_possible_values_*` | The PHI handler unions incomings (also covers cast-width preservation and rolled-arithmetic-chain enumeration). |

When changing loop handling, run at minimum:

```
python test.py micro
python test.py baseline
```

For changes that touch register/flag phi shape, also re-run the Themida sample to confirm the 2544-instruction benchmark holds:

```
build_iced\lifter.exe ..\testthemida\example2-virt.bin 0x140001000
```

and inspect `output_diagnostics.json` for `lift_stats.instructions_lifted == 2544` and `summary.warning == 0`, `summary.error == 0`.

## Known limitations

| Limitation | Status |
|---|---|
| `REP`/`REPE`/`REPNE`-prefixed `SCAS` | Rejected as `not_implemented`; needs a model for repeated-scan termination. |
| `INT 2` continuation under VMP 3.6 | Naive architectural fallthrough is wrong; recovery requires modeling the dispatcher / exception-mediated control flow. See `VMP_TESTING_NOTES.md`. |
| Hardcoded `(address, offset)` pairs in `resolveTargetedThemidaR9` | Only fire on the reference Themida sample. See [Hardcoded reference-sample addresses](#hardcoded-reference-sample-addresses). |
| Loop unrolling / loop-invariant code motion | Not implemented. The lifter relies on LLVM's downstream optimization passes for this once the IR is in shape. |
| Multi-way backedges (≥3 paths to the same header) | Not exercised by the current generalized-loop machinery; the canonical/backedge model assumes exactly two incoming paths. |
