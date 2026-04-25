# vm_signedaccum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signedaccum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signedaccum64_loop.ll`
- **Symbol:** `vm_signedaccum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signedaccum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signedaccum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1: val=0, sub stays 0 |
| 2 | RCX=1 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | x=1, n=2: i=0 add 0, i=1 sub 1 -> -1 u64 |
| 3 | RCX=7 | 18446744073709551462 | 18446744073709551462 | 18446744073709551462 | yes | x=7, n=8 |
| 4 | RCX=31 | 18446744073709536860 | 18446744073709536860 | 18446744073709536860 | yes | x=0x1F, n=32 max |
| 5 | RCX=255 | 18446744073709439416 | 18446744073709439416 | 18446744073709439416 | yes | x=0xFF, n=32 |
| 6 | RCX=51966 | 18446744073693389879 | 18446744073693389879 | 18446744073693389879 | yes | x=0xCAFE, n=31 |
| 7 | RCX=3405691582 | 487013896369 | 487013896369 | 487013896369 | yes | x=0xCAFEBABE, n=31 |
| 8 | RCX=1311768467463790320 | 10248191152060861202 | 10248191152060861202 | 10248191152060861202 | yes | 0x123...DEF0, n=17 |
| 9 | RCX=18446744073709551615 | 18446744073709551120 | 18446744073709551120 | 18446744073709551120 | yes | max u64, n=32: all-add 0..31 * max |
| 10 | RCX=11400714819323198485 | 5775349131336018377 | 5775349131336018377 | 5775349131336018377 | yes | K (golden), n=22 |

## Source

```c
/* PC-state VM with a SIGNED accumulator that adds or subtracts a derived
 * i64 value per iteration, gated by the input bit at the loop counter.
 *   s = 0; n = (x & 0x1F) + 1; base = x | 1;
 *   for i in 0..n:
 *     val = i * base
 *     if (x >> i) & 1:  s += val
 *     else:              s -= val
 *   return s;
 * Lift target: vm_signedaccum64_loop_target.
 *
 * Distinct from vm_condsum64_loop (one-sided gated +) and vm_oddcount64_loop
 * (gated +1): two mutually-exclusive update branches with TWO directions
 * (add vs subtract) on the SAME accumulator slot.  Single counter avoids
 * the dual-i64 pseudo-stack failure documented in vm_dualcounter64.
 */
#include <stdio.h>
#include <stdint.h>

enum SgVmPc {
    SG_LOAD       = 0,
    SG_INIT       = 1,
    SG_LOOP_CHECK = 2,
    SG_LOOP_BODY  = 3,
    SG_LOOP_INC   = 4,
    SG_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_signedaccum64_loop_target(uint64_t x) {
    int      idx  = 0;
    int      n    = 0;
    uint64_t xx   = 0;
    uint64_t base = 0;
    uint64_t s    = 0;
    int      pc   = SG_LOAD;

    while (1) {
        if (pc == SG_LOAD) {
            xx   = x;
            n    = (int)(x & 0x1Full) + 1;
            base = x | 1ull;
            s    = 0ull;
            pc = SG_INIT;
        } else if (pc == SG_INIT) {
            idx = 0;
            pc = SG_LOOP_CHECK;
        } else if (pc == SG_LOOP_CHECK) {
            pc = (idx < n) ? SG_LOOP_BODY : SG_HALT;
        } else if (pc == SG_LOOP_BODY) {
            uint64_t val = (uint64_t)idx * base;
            if (((xx >> idx) & 1ull) != 0ull) {
                s = s + val;
            } else {
                s = s - val;
            }
            pc = SG_LOOP_INC;
        } else if (pc == SG_LOOP_INC) {
            idx = idx + 1;
            pc = SG_LOOP_CHECK;
        } else if (pc == SG_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedaccum64(0xCAFE)=%llu vm_signedaccum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signedaccum64_loop_target(0xCAFEull),
           (unsigned long long)vm_signedaccum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
