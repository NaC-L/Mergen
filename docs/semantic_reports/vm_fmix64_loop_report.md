# vm_fmix64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_fmix64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_fmix64_loop.ll`
- **Symbol:** `vm_fmix64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_fmix64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_fmix64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: zero stays zero (no shift contribution) |
| 2 | RCX=1 | 9038243705893100514 | 9038243705893100514 | 9038243705893100514 | yes | x=1, n=2 |
| 3 | RCX=7 | 8486797414100562630 | 8486797414100562630 | 8486797414100562630 | yes | x=7, n=8 max |
| 4 | RCX=255 | 12226072129499856351 | 12226072129499856351 | 12226072129499856351 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 5965516933220053433 | 5965516933220053433 | 5965516933220053433 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 1408996039744156717 | 1408996039744156717 | 1408996039744156717 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 1781385183907554200 | 1781385183907554200 | 1781385183907554200 | yes | x=0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 14764577206887631716 | 14764577206887631716 | 14764577206887631716 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 2186571374379122088 | 2186571374379122088 | 2186571374379122088 | yes | x=K (golden), n=6 |
| 10 | RCX=3735928559 | 10102246366604652111 | 10102246366604652111 | 10102246366604652111 | yes | x=0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running the MurmurHash3 fmix64 final-mixer in a
 * variable-trip loop.  Per iteration:
 *   state ^= state >> 33;
 *   state *= 0xFF51AFD7ED558CCD;
 *   state ^= state >> 33;
 *   state *= 0xC4CEB9FE1A85EC53;
 *   state ^= state >> 33;
 * Variable trip n = (x & 7) + 1.  Returns full uint64_t.
 * Lift target: vm_fmix64_loop_target.
 *
 * Distinct from vm_xorshift64_loop (3-step shift+xor without mul) and
 * vm_pcg64_loop (single mul + add): exercises an alternating xor-shift
 * and multiply-by-large-constant chain (5 ops per iteration) on full i64.
 */
#include <stdio.h>
#include <stdint.h>

enum FmVmPc {
    FM_LOAD       = 0,
    FM_INIT       = 1,
    FM_LOOP_CHECK = 2,
    FM_LOOP_BODY  = 3,
    FM_LOOP_INC   = 4,
    FM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_fmix64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = FM_LOAD;

    while (1) {
        if (pc == FM_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = FM_INIT;
        } else if (pc == FM_INIT) {
            idx = 0;
            pc = FM_LOOP_CHECK;
        } else if (pc == FM_LOOP_CHECK) {
            pc = (idx < n) ? FM_LOOP_BODY : FM_HALT;
        } else if (pc == FM_LOOP_BODY) {
            state = state ^ (state >> 33);
            state = state * 0xFF51AFD7ED558CCDull;
            state = state ^ (state >> 33);
            state = state * 0xC4CEB9FE1A85EC53ull;
            state = state ^ (state >> 33);
            pc = FM_LOOP_INC;
        } else if (pc == FM_LOOP_INC) {
            idx = idx + 1;
            pc = FM_LOOP_CHECK;
        } else if (pc == FM_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fmix64(0xCAFE)=%llu vm_fmix64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_fmix64_loop_target(0xCAFEull),
           (unsigned long long)vm_fmix64_loop_target(0xDEADBEEFull));
    return 0;
}
```
