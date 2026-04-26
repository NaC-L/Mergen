# Architecture Reference

## Key Constants

| Constant | Value | Defined in |
|---|---|---|
| `STACKP_VALUE` | `0x14FEA0` | `lifter/core/Includes.h` |
| Stack reserve min | `0x1000` | `lifter/memory/MemoryPolicySetup.hpp` (`configureDefaultMemoryPolicy`) |
| Stack reserve max | `0x100000` | `lifter/memory/MemoryPolicySetup.hpp` (`configureDefaultMemoryPolicy`) |

## Pipeline Order

| # | Function | File | Purpose |
|---|---|---|---|
| 1 | `createRuntimeImageContext` | `lifter/core/RuntimeImageContext.hpp` | Validates PE headers, builds `RuntimeImageContext` |
| 2 | `createConfiguredLifterForRuntime` | `lifter/core/LifterStages.hpp` | Calls `loadFile`, parses PE exports, auto-outlines export addresses |
| 3 | `configureDefaultMemoryPolicy` | `lifter/memory/MemoryPolicySetup.hpp` | Sets `memoryPolicy` (SYMBOLIC default, CONCRETE for PE sections + stack), clamps `stackReserve` to `[0x1000, 0x100000]` |
| 4 | `prepareRuntimePagedMemory` | `lifter/core/LifterPipelineStages.hpp` | Marks `pageMap` intervals for mapped memory regions |
| 5 | `runSignatureStage` | `lifter/core/LifterPipelineStages.hpp` | Signature-based analysis |
| 6 | Lift loop | `lifter/core/LiftDriver.hpp` | Main lifting of instructions to LLVM IR |
| 7 | `run_opts` | `lifter/core/MergenPB.hpp` | Fixpoint optimization (see below) |

## run_opts Fixpoint Loop

```
loop {
    O1 pipeline
    GEPLoadPass
    ReplaceTruncWithLoadPass
    PromotePseudoStackPass
    PromotePseudoMemory
} until instruction count stabilizes (delta == 0)

Final O2 pipeline (runs once after fixpoint)
```

Termination: the loop compares instruction count before and after each iteration. When the count stops changing, the fixpoint is reached.

Iteration cap: the loop bails out after 64 iterations and emits a `FixpointMaxIterations` warning diagnostic. This is a safety net against pass oscillation, not an expected termination path.

Observability: each iteration is recorded into `fixpointStats.iteration_log` and emitted under the `optimization` section of `output_diagnostics.json`. Per-iteration fields: `before`, `after_o1`, `after_geploadpass`, `after_replacetrunc`, `after_promotestack`, `after_promotemem`, plus per-pass `*_ms` timings and total `ms`. The four custom passes are run as separate `ModulePassManager` invocations so per-pass instruction-count delta and wall-clock cost are observable; O1 is recorded as a single bundle. Module-level fields: `iterations`, `reached_cap`, `initial_size`, `final_loop_size`, `final_o2_size`, `final_post_size`.

## Custom Pass Summary

| Pass | Filters on | Produces | Description |
|---|---|---|---|
| `GEPLoadPass` | `memory`-base GEPs where: `getPointerOperand() == mem`, `!isSymbolic`, `address_to_mapped_address != 0`, `isIntegerTy()`, `readMemory` succeeds | Constant integer values folded from PE image | Folds constant loads from the PE image through `memory`-base GEPs |
| `ReplaceTruncWithLoadPass` | `trunc(load wide, ptr)` patterns | `load narrow, ptr` | Rewrites wide-load-then-truncate into narrow load; valid on little-endian |
| `PromotePseudoStackPass` | `memory`-base GEPs in `[STACKP_VALUE - reserve, STACKP_VALUE + reserve]` via `isStackAddress()` | `stackmemory` alloca GEPs | Replaces pseudo-stack memory accesses with real stack alloca operations |
| `PromotePseudoMemory` | Remaining `memory`-base GEPs (not handled by above passes) | `inttoptr` | Converts leftover pseudo-memory GEPs to raw pointer operations |

Pass order matters: GEPLoadPass must run before PromotePseudoMemory, otherwise concrete PE loads get converted to `inttoptr` and are lost.

## InlinePolicy

- **CRTP framework**: default policy inlines everything.
- **Outline set**: `addAddress(va)` registers a VA for outlining (i.e., not inlined).
- **Check site**: `Semantics_ControlFlow.ipp:202` — when a call target is constant-resolved, the inline policy is consulted.
- **CLI**: `--outline <addrs>` accepts comma-separated hex addresses, parsed in `Utils.cpp`, stored in `ParseResult::outlineAddresses`.
- **PE export auto-outline**: export addresses are automatically added to the outline set in `createConfiguredLifterForRuntime`. Forwarded exports are filtered out by checking if the RVA falls within the export directory range.

## Memory Subsystem

### FileReader

CRTP base with concrete implementations `x86FileReader` and `x86_64FileReader`.

| Method | Returns | Failure value |
|---|---|---|
| `RvaToFileOffset` | file offset | `0` |
| `readMemory` | `bool` | `false` |
| `address_to_mapped_address` | mapped address | `0` |

### MemoryPolicy

| Region | Policy |
|---|---|
| Default | SYMBOLIC |
| PE sections | CONCRETE |
| Stack | CONCRETE |

Set by `configureDefaultMemoryPolicy` in `lifter/memory/MemoryPolicySetup.hpp`.

### pageMap

`std::map<uint64_t, uint64_t>` — interval map of paged memory regions.

- `markMemPaged(start, end)` — inserts an interval.
- `isMemPaged` — uses `upper_bound` then decrements iterator to check containment.

### stackReserve

Set by `configureDefaultMemoryPolicy`, clamped to `[0x1000, 0x100000]`. Consumed by:
- `PromotePseudoStackPass` — defines the stack address window around `STACKP_VALUE`
- `prepareRuntimePagedMemory` — marks the stack region in `pageMap`

## PE Parsing

- Header types come from the **linuxpe** library.
- `RvaToFileOffset` returns `0` on failure — callers must check before using the offset.
- Export directory is parsed in `createConfiguredLifterForRuntime`; forwarded exports are detected by checking if the export RVA falls within the export directory VA range.
- `RuntimeImageContext` is validated in `createRuntimeImageContext` (step 1 of the pipeline).
