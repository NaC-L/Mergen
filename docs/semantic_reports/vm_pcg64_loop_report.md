# vm_pcg64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_pcg64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_pcg64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_pcg64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_pcg64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0, n=1: 0*K+1=1 |
| 2 | RCX=1 | 13885033947626072944 | 13885033947626072944 | 13885033947626072944 | yes | x=1, n=2 |
| 3 | RCX=7 | 10510407654128065718 | 10510407654128065718 | 10510407654128065718 | yes | x=7, n=8 max |
| 4 | RCX=255 | 9423786968930507423 | 9423786968930507423 | 9423786968930507423 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 16332309564354265995 | 16332309564354265995 | 16332309564354265995 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 4923375292513170454 | 4923375292513170454 | 4923375292513170454 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 10221792657023290640 | 10221792657023290640 | 10221792657023290640 | yes | x=0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 16496022540416410939 | 16496022540416410939 | 16496022540416410939 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 410937713162742993 | 410937713162742993 | 410937713162742993 | yes | x=K (golden), n=6 |
| 10 | RCX=21930 | 9846016891212640976 | 9846016891212640976 | 9846016891212640976 | yes | x=0x55AA, n=3 |

## Source

```c
/* PC-state VM running a PCG-style i64 RNG.
 *   state = x;
 *   for i in 0..n: state = state * 0x5851F42D4C957F2D + 1;
 *   return state ^ (state >> 33);
 * Variable trip n = (x & 7) + 1 (1..8).  Returns full uint64_t.
 * Lift target: vm_pcg64_loop_target.
 *
 * Distinct from vm_pcg_loop (i32 PCG) and vm_lcg_loop: exercises a
 * 64-bit LCG step (full i64 mul + add) followed by an XOR-shift mix
 * for output extraction.
 */
#include <stdio.h>
#include <stdint.h>

enum PgVmPc {
    PG_LOAD       = 0,
    PG_INIT       = 1,
    PG_LOOP_CHECK = 2,
    PG_LOOP_BODY  = 3,
    PG_LOOP_INC   = 4,
    PG_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pcg64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = PG_LOAD;

    while (1) {
        if (pc == PG_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = PG_INIT;
        } else if (pc == PG_INIT) {
            idx = 0;
            pc = PG_LOOP_CHECK;
        } else if (pc == PG_LOOP_CHECK) {
            pc = (idx < n) ? PG_LOOP_BODY : PG_HALT;
        } else if (pc == PG_LOOP_BODY) {
            state = state * 0x5851F42D4C957F2Dull + 1ull;
            pc = PG_LOOP_INC;
        } else if (pc == PG_LOOP_INC) {
            idx = idx + 1;
            pc = PG_LOOP_CHECK;
        } else if (pc == PG_HALT) {
            return state ^ (state >> 33);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pcg64(0xCAFE)=%llu vm_pcg64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pcg64_loop_target(0xCAFEull),
           (unsigned long long)vm_pcg64_loop_target(0xCAFEBABEull));
    return 0;
}
```
