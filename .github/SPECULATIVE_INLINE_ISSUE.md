# Speculative call inlining: policy design for inline vs outline

## Problem

The lifter must decide at each `call` instruction whether to:
- **Inline** (follow the callee, deobfuscate its code, merge into the caller) 
- **Outline** (emit `CreateCall` + ABI effects, continue at the next instruction)

For obfuscated binaries (VMP, Themida), the `call` instruction is used as a control-flow gadget: `call` to push RIP, `push+ret` as indirect jumps, `call` into VM handler tables. These MUST be inlined for deobfuscation to work.

For real function calls (cout, printf, kernel32 APIs, statically-linked CRT), following the callee leads into code that's too complex and unrelated to the function's semantics. These SHOULD be outlined.

The challenge: both cases look identical at the `call` instruction. There's no local heuristic that distinguishes them.

## Current state (after 6d0157f)

### What works
- **Import thunk detection**: `jmp [rip+disp32]` (FF 25) that reads from IAT and points outside the binary is auto-outlined. Handles dynamically-linked APIs.
- **Indirect/symbolic calls**: Non-constant targets (e.g., `call r9`) emit CreateCall automatically.
- **Speculative inlining mechanism**: A budget-limited approach that tries to inline and bails out if the callee exceeds N instructions. Disabled by default (`maxCallInlineBudget = 0`) because it interferes with VMP which needs 14,000+ instructions.

### What doesn't work
- **Statically-linked library calls** (calc_cout's `operator<<`): Target is at a constant in-binary address. Not an import thunk. The lifter follows it into thousands of instructions of STL code and gets lost.
- **Global instruction budget** conflicts with VMP: VMP's entry `call` looks the same as `calc_cout`'s library call. A budget of 500 correctly bails out of cout but kills VMP deobfuscation.

## Analysis

| Call pattern | Inline? | Detection method |
|---|---|---|
| `call` to VM entry (VMP) | YES | Must inline everything — VM body is the function |
| `push+ret` / `call $+5; pop rax` gadgets | YES | Already inlined (Unflatten path follows them) |
| `call [rip+IAT]` (DLL import) | NO | Detected: FF 25 thunk → external address |
| `call r9` (indirect via register) | NO | Detected: non-constant target → CreateCall |
| `call operator<<` (statically-linked) | NO | **Not detected** — looks like any other constant call |

## Proposed approaches

### A. Call-depth scoped budget
Track call nesting depth. The *first* `call` from the root function entry always inlines (handles VMP entry). Calls at depth >= 1 get a speculative budget. If the nested callee exceeds N instructions, bail out.

**Pro**: VMP works (single entry call at depth 0). Library calls from within a non-obfuscated caller get caught at depth 1.
**Con**: If the root function IS a library-calling function (like calc_cout), the first call still goes deep. Also, VMP functions that contain genuine API calls via `call` (not push+ret) would incorrectly inline them.

### B. Pre-analysis probe
Before inlining a `call`, disassemble (not lift) the target's first N bytes without IR emission. Check for standard function prologue (`sub rsp`, `push rbx`, etc.) and estimate complexity. If it looks like a large standard function, outline it.

**Pro**: No false positive on VM handlers (they don't have standard prologues). Deterministic.
**Con**: Some STL functions have short prologues. Requires a disassembly pass separate from lifting.

### C. PE metadata (`.pdata` + `.idata`)
Use `.pdata` to identify function boundaries. If the call target is the start of a DIFFERENT `.pdata` entry (a different function), outline it. VM handler code typically doesn't have `.pdata` entries.

**Pro**: Very accurate for non-obfuscated code. Zero false positives on import thunks.
**Con**: VMP-protected binaries may strip `.pdata` or have fake entries. Relies on metadata that obfuscators can tamper with.

### D. User-specified outline list (`--outline addr1,addr2,...`)
Let the user explicitly mark addresses to outline. The lifter already has `inlinePolicy.addAddress()` infrastructure.

**Pro**: No false positives. User is the oracle.
**Con**: Requires manual analysis to determine which addresses to outline. Not automatic.

### E. Hybrid: import thunk + call-depth budget + CLI override
- Layer 1: Auto-outline import thunks (already done)
- Layer 2: Call-depth budget for nested calls (depth >= 1 gets speculative budget)
- Layer 3: `--outline` CLI flag for manual overrides

This is the most practical path forward.

## Acceptance criteria
- calc_cout lifts correctly: `x * 3 + 7` with an outlined call to `operator<<`
- VMP target unchanged: clean `a + b + c` deobfuscation
- No false outlining of VM handlers or obfuscation gadgets
- Existing test suite stays green

## Related
- `AbiCallContract.hpp` — call effects framework
- `SpeculativeCallInfo` struct in `LifterClass.hpp` — speculative mechanism
- `maxCallInlineBudget` — budget knob (currently 0 = disabled)
