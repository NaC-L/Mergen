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

## Control-Flow Recognition

The lift loop recognizes several `ret`/`jmp` shapes beyond a plain return or branch and emits structured IR for them instead of falling through to `solvePath`.

### Real return vs ROP/continuation return

`lift_ret` (`Semantics_ControlFlow.ipp`) classifies the return on entry:

- If RSP folds to the constant `STACKP_VALUE`, this is a return from the outermost (entry) frame. Emit a clean `ret rax` via `emitResolvedFunctionReturn` and stop the lift loop.
- Otherwise the return is treated as a ROP/continuation return: pop the return target, advance RSP by `ptrSize` (plus the immediate for `ret imm16`), and try to resolve the popped target via `solvePath`. If that fails, the `UnresolvedRetChain` diagnostic is recorded and the block is degraded to a `ret rax` to keep the IR well-formed.

### Ret-to-IAT chain (Themida-virt)

Themida-virt and similar protectors rewrite each `call [rip+IAT]` site as a VM-staged `push target; ret`, where `target` was loaded from the IAT by an upstream VM handler. The original code's semantics consume two stack slots: `ret` pops the IAT slot into RIP (calling the import), then the import's own `ret` pops the continuation address.

When the popped target is a constant in `importMap`, `lift_ret` collapses both pops into one structural emission:

1. Read the next stack slot (`[RSP+ptrSize]`); if it is also a constant, treat it as the continuation VA `contVA`.
2. Advance RSP by another `ptrSize` so it reflects both pops (the import's return + the original ret). Emitted as `ret-chain-cont-rsp-...` in the IR.
3. Emit `call @<import>` with an empty `volatileRegs` set so the lifter does not clobber caller-saved GPRs across the external call -- VM dispatchers preserve their own caller-saved state across import calls in the real binary.
4. Emit `br contBB`, queue `contVA` for lifting if not already visited, record the site in `chainedImportRetSites` so the unresolved-ret diagnostic is suppressed for this address, and stop the per-instruction lift loop for the current block.

Without the RSP advance in step 2, the continuation block sees RSP off by one slot (entry RSP + 8 instead of + 16). For `example2` the post-O2 IR shows only SSA-renumbering churn across the fix because no `[rsp+N]` read in the continuation flows to a visible computation, but the invariant still holds and is gated by the `ret_to_iat_chain_advances_rsp_by_two_slots` microtest.

### Direct vs indirect jumps

`lift_jmp` discriminates on `instruction.types[0]`: `Immediate8`/`Immediate16`/`Immediate32`/`Immediate64` are direct (RIP-relative) jumps, everything else is indirect. For direct jumps the immediate is sign-extended and added to RIP to form the absolute target. Both forms then go through `solvePath`; if the path solver cannot resolve the target, the `UnresolvedIndirectJump` diagnostic is recorded (no inline `std::cout` print -- the diagnostics framework persists it to `output_diagnostics.json`).

### Operand-type quirks

Iced classifies operand types by the bytes the instruction actually accesses, not by physical register/memory width. SSE handlers that gate on `Register128`/`Memory128` only must also accept `Register64`/`Memory64` for instructions whose semantics read fewer bytes than the encoding nominally allows. PUNPCKLQDQ is the canonical example: the encoding is `xmm/m128` but only the low 64 bits of the source are read, so Iced reports `Register64`/`Memory64`. The `sse_memory_form_handlers_do_not_fall_through_to_not_implemented` microtest gates this for `pand`/`por`/`pxor` to catch future Iced reclassifications before they silently reach a `not_implemented; ret` lowering.


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
