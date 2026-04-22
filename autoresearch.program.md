# Autoresearch Program Notes

## Durable heuristics
- Treat the unresolved Themida `0x140001000` frontier as a real parser/state-machine loop, not random CFG noise.
- The decisive evolving state is the control cursor local slot at `0x14004DD19`, but the useful abstraction boundary is downstream derived-field loads, not a raw memory-PHI merge of the slot itself.
- The first visible dispatch lookup around `0x140023799` is already concrete on baseline. Missing progress begins on the second feedback pass, so optimize for preserving symbolic relationships through that pass.
- Generalized-loop support is already split across two layers:
  - `LifterClass_Concolic.hpp` preserves canonical vs backedge state and exposes exact generalized-loop local bytes.
  - `GEPTracker.ipp::solveLoad(...)` is where symbolic load addresses are interpreted into concrete or symbolic values.
- For this target, broad buffer-level memory PHIs are too expensive semantically. Prefer narrow address-shape recognition in `solveLoad(...)` over generic tracked-memory merging.

## Repo-specific strategy
- Start from the clean benchmark baseline and make one coherent experiment at a time.
- Bias changes toward `solveLoad(...)` in Unflatten mode; only touch generalized-loop restore plumbing if the address-shape helper cannot be expressed there.
- Add focused `Tester.hpp` coverage for any new generalized-loop derived-load helper before trusting benchmark gains.
- Keep checks strict: warnings/errors/unsupported instructions must remain zero even when the frontier advances.
