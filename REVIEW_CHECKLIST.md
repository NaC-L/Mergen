# Mergen Review Checklist

Use this as the quick reviewer companion.
- Workflow, severity, and verification matrix live in `docs/REVIEWER_RULES.md`.
- LLVM API gotchas and erase/RAUW reminders live in `LLVM_API_NOTES.md`.

## Custom Pass / IR Safety
- [ ] Iterator invalidation is avoided during IR erasure (`it++` before erase or collect-then-erase)
- [ ] `replaceAllUsesWith()` is followed by correct dead-instruction cleanup
- [ ] Erase collections deduplicate `Instruction*` values before destruction
- [ ] `getIntegerBitWidth()` / `computeKnownBits()` are guarded by type checks
- [ ] GEP-based passes filter on the correct base pointer (`memory`, `stackmemory`, etc.)
- [ ] Passes return the correct preserved-analysis state after mutation

## Runtime Image / Memory Invariants
- [ ] `RvaToFileOffset`, `readMemory`, and `address_to_mapped_address` failure values are checked before use
- [ ] Stack arithmetic cannot underflow or diverge from the clamped reserve window
- [ ] `pageMap`, `memoryPolicy`, and stack-promotion logic derive bounds from the same source of truth
- [ ] PE export parsing filters forwarded exports before adding outline targets

## Call / ABI Behavior
- [ ] Unknown or outlined calls preserve the intended ABI contract for the chosen mode
- [ ] Strict-mode clobbers and memory effects remain consistent with `AbiCallContract.hpp`
- [ ] Compat-mode behavior remains opt-in and diagnostic-only

## Rewrite Manifests / Vectors / Tests
- [ ] `scripts/rewrite/instruction_microtests.json` stays in one-to-one sync with `testcases/rewrite_smoke/`
- [ ] Manifest sample names reject traversal/path separators
- [ ] Oracle/vector schema fields keep their expected types (`skip` stays boolean, XMM values stay fixed-width)
- [ ] Golden-hash churn is explained; C/C++-compiled samples are not treated like deterministic asm outputs

## Documentation / Process
- [ ] `cmake.toml` is updated instead of hand-editing generated `CMakeLists.txt`
- [ ] Docs changed with behavior when defaults, commands, or invariants moved
- [ ] Verification commands in the PR match the changed subsystem
