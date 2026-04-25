# vm_fmix_chain64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_fmix_chain64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_fmix_chain64_loop.ll`
- **Symbol:** `vm_fmix_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_fmix_chain64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_fmix_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 across all iters |
| 2 | RCX=1 | 898201889658528104 | 898201889658528104 | 898201889658528104 | yes | x=1 n=2: two fmix rounds |
| 3 | RCX=2 | 8693572102153751765 | 8693572102153751765 | 8693572102153751765 | yes | x=2 n=3 |
| 4 | RCX=7 | 3494767213575592779 | 3494767213575592779 | 3494767213575592779 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 5092388815683068117 | 5092388815683068117 | 5092388815683068117 | yes | x=8 n=1: single fmix round |
| 6 | RCX=3405691582 | 9387636944915422948 | 9387636944915422948 | 9387636944915422948 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 1268616178070044434 | 1268616178070044434 | 1268616178070044434 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 2909846994098041682 | 2909846994098041682 | 2909846994098041682 | yes | all 0xFF: n=8 |
| 9 | RCX=72623859790382856 | 15109312571383956947 | 15109312571383956947 | 15109312571383956947 | yes | 0x0102...0708: n=1 single round |
| 10 | RCX=1311768467463790320 | 1781385183969690537 | 1781385183969690537 | 1781385183969690537 | yes | 0x12345...EF0: n=1 |

## Source

```c
/* PC-state VM that applies the Murmur3 64-bit finalizer n times in a row:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r ^= r >> 33;
 *     r *= 0xFF51AFD7ED558CCD;
 *     r ^= r >> 33;
 *     r *= 0xC4CEB9FE1A85EC53;
 *   }
 *   // (no trailing fold here, so r is the cycled state)
 *   return r;
 *
 * Lift target: vm_fmix_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_fmix64_loop      (single fmix application, no loop)
 *   - vm_xxhmix64_loop    (per-byte mix; one mul; xor-fold OUTSIDE loop)
 *   - vm_murmurstep64_loop (single magic; xor-with-input each iter)
 *   - vm_splitmix64_loop  (different magics; constant additive step)
 *
 * Tests dual-magic xor-mul-xor-mul finalizer chain inside a counter
 * loop body.  Each iteration applies four sequential ops on a single
 * i64 accumulator: lshr-33 + xor, mul-by-magic1, lshr-33 + xor,
 * mul-by-magic2.  Single-state, no byte windowing.
 */
#include <stdio.h>
#include <stdint.h>

enum FxVmPc {
    FX_INIT_ALL = 0,
    FX_CHECK    = 1,
    FX_BODY     = 2,
    FX_INC      = 3,
    FX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_fmix_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FX_INIT_ALL;

    while (1) {
        if (pc == FX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = FX_CHECK;
        } else if (pc == FX_CHECK) {
            pc = (i < n) ? FX_BODY : FX_HALT;
        } else if (pc == FX_BODY) {
            r = r ^ (r >> 33);
            r = r * 0xFF51AFD7ED558CCDull;
            r = r ^ (r >> 33);
            r = r * 0xC4CEB9FE1A85EC53ull;
            pc = FX_INC;
        } else if (pc == FX_INC) {
            i = i + 1ull;
            pc = FX_CHECK;
        } else if (pc == FX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fmix_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fmix_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
```
