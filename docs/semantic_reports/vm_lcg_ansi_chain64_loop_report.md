# vm_lcg_ansi_chain64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_lcg_ansi_chain64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_lcg_ansi_chain64_loop.ll`
- **Symbol:** `vm_lcg_ansi_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_lcg_ansi_chain64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_lcg_ansi_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 12345 | 12345 | 12345 | yes | x=0 n=1: 0*A+12345=12345 |
| 2 | RCX=1 | 1217759518843121895 | 1217759518843121895 | 1217759518843121895 | yes | x=1 n=2 |
| 3 | RCX=2 | 13429379559266951497 | 13429379559266951497 | 13429379559266951497 | yes | x=2 n=3 |
| 4 | RCX=7 | 15269757630230227199 | 15269757630230227199 | 15269757630230227199 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 8828134305 | 8828134305 | 8828134305 | yes | x=8 n=1: 8*A+12345 |
| 6 | RCX=3405691582 | 5394996920446395057 | 5394996920446395057 | 5394996920446395057 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 7100797012767448295 | 7100797012767448295 | 7100797012767448295 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 14013565258359107575 | 14013565258359107575 | 14013565258359107575 | yes | all 0xFF n=8 |
| 9 | RCX=72623859790382856 | 7289336239468420769 | 7289336239468420769 | 7289336239468420769 | yes | 0x0102...0708: n=1 single LCG step |
| 10 | RCX=1311768467463790320 | 3689348795830123625 | 3689348795830123625 | 3689348795830123625 | yes | 0x12345...EF0: n=1 |

## Source

```c
/* PC-state VM running the classic ANSI C rand() LCG over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r * 1103515245 + 12345;   // ANSI rand() constants
 *   }
 *   return r;
 *
 * Lift target: vm_lcg_ansi_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xorrot64_loop          (LCG with golden-ratio multiplier + xor accum)
 *   - vm_pcg64_loop             (PCG random)
 *   - vm_xorshift64_loop        (Marsaglia three-shift xorshift)
 *   - vm_squareadd64_loop       (single-state quadratic recurrence)
 *
 * Tests linear-congruential recurrence with the canonical ANSI C
 * rand() multiplier (1103515245) and increment (12345) chained for
 * n iterations.  Single i64 state, no input read inside the body
 * (only seeded by x at INIT_ALL).
 */
#include <stdio.h>
#include <stdint.h>

enum LcVmPc {
    LC_INIT_ALL = 0,
    LC_CHECK    = 1,
    LC_BODY     = 2,
    LC_INC      = 3,
    LC_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_lcg_ansi_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = LC_INIT_ALL;

    while (1) {
        if (pc == LC_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = LC_CHECK;
        } else if (pc == LC_CHECK) {
            pc = (i < n) ? LC_BODY : LC_HALT;
        } else if (pc == LC_BODY) {
            r = r * 1103515245ull + 12345ull;
            pc = LC_INC;
        } else if (pc == LC_INC) {
            i = i + 1ull;
            pc = LC_CHECK;
        } else if (pc == LC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lcg_ansi_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_lcg_ansi_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
```
