# vm_lcg_ansi_chain64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_lcg_ansi_chain64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_lcg_ansi_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_lcg_ansi_chain64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_lcg_ansi_chain64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_lcg_ansi_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 12345 | 12345 | — | **no** | x=0 n=1: 0*A+12345=12345 |
| 2 | RCX=1 | 1217759518843121895 | 1217759518843121895 | — | **no** | x=1 n=2 |
| 3 | RCX=2 | 13429379559266951497 | 13429379559266951497 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 15269757630230227199 | 15269757630230227199 | — | **no** | x=7 n=8: max trip |
| 5 | RCX=8 | 8828134305 | 8828134305 | — | **no** | x=8 n=1: 8*A+12345 |
| 6 | RCX=3405691582 | 5394996920446395057 | 5394996920446395057 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 7100797012767448295 | 7100797012767448295 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 14013565258359107575 | 14013565258359107575 | — | **no** | all 0xFF n=8 |
| 9 | RCX=72623859790382856 | 7289336239468420769 | 7289336239468420769 | — | **no** | 0x0102...0708: n=1 single LCG step |
| 10 | RCX=1311768467463790320 | 3689348795830123625 | 3689348795830123625 | — | **no** | 0x12345...EF0: n=1 |

## Failure detail

### case 1: x=0 n=1: 0*A+12345=12345

- inputs: `RCX=0`
- manifest expected: `12345`
- native: `12345`
- lifted: `—`

### case 2: x=1 n=2

- inputs: `RCX=1`
- manifest expected: `1217759518843121895`
- native: `1217759518843121895`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `13429379559266951497`
- native: `13429379559266951497`
- lifted: `—`

### case 4: x=7 n=8: max trip

- inputs: `RCX=7`
- manifest expected: `15269757630230227199`
- native: `15269757630230227199`
- lifted: `—`

### case 5: x=8 n=1: 8*A+12345

- inputs: `RCX=8`
- manifest expected: `8828134305`
- native: `8828134305`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `5394996920446395057`
- native: `5394996920446395057`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `7100797012767448295`
- native: `7100797012767448295`
- lifted: `—`

### case 8: all 0xFF n=8

- inputs: `RCX=18446744073709551615`
- manifest expected: `14013565258359107575`
- native: `14013565258359107575`
- lifted: `—`

### case 9: 0x0102...0708: n=1 single LCG step

- inputs: `RCX=72623859790382856`
- manifest expected: `7289336239468420769`
- native: `7289336239468420769`
- lifted: `—`

### case 10: 0x12345...EF0: n=1

- inputs: `RCX=1311768467463790320`
- manifest expected: `3689348795830123625`
- native: `3689348795830123625`
- lifted: `—`

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
