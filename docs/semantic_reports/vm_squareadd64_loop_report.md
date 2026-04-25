# vm_squareadd64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_squareadd64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_squareadd64_loop.ll`
- **Symbol:** `vm_squareadd64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_squareadd64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_squareadd64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 (0*0+0=0) |
| 2 | RCX=1 | 2 | 2 | 2 | yes | x=1 n=2: r=1->1+0=1->1+1=2 |
| 3 | RCX=2 | 291 | 291 | 291 | yes | x=2 n=3 |
| 4 | RCX=3 | 45239079 | 45239079 | 45239079 | yes | x=3 n=4 |
| 5 | RCX=7 | 9195696129828624491 | 9195696129828624491 | 9195696129828624491 | yes | x=7 n=8: max trip |
| 6 | RCX=8 | 64 | 64 | 64 | yes | x=8 n=1: r=64+0=64 |
| 7 | RCX=3405691582 | 972137993493440703 | 972137993493440703 | 972137993493440703 | yes | 0xCAFEBABE: n=7 |
| 8 | RCX=3735928559 | 2025791209710884971 | 2025791209710884971 | 2025791209710884971 | yes | 0xDEADBEEF: n=8 (low nibble=F-> low3=7) |
| 9 | RCX=18446744073709551615 | 6702382813236303979 | 6702382813236303979 | 6702382813236303979 | yes | all 0xFF: n=8 |
| 10 | RCX=1311768467463790320 | 11953125779633938688 | 11953125779633938688 | 11953125779633938688 | yes | 0x12345...EF0: n=1: r=x*x mod 2^64 |

## Source

```c
/* PC-state VM that drives a counter-bound quadratic recurrence:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) r = r*r + i;
 *   return r;   // u64, modular
 *
 * Lift target: vm_squareadd64_loop_target.
 *
 * Distinct from:
 *   - vm_geosum64_loop (multiply-by-constant + add accumulator)
 *   - vm_powmod64_loop (modexp with squaring + reduction)
 *   - vm_choosemax64_loop (pick larger of two derived options)
 *
 * Single-state u64 quadratic: r = r*r + i.  Each iteration squares
 * the accumulator and adds the loop index, exercising i64 mul on
 * mid-loop values that grow quickly mod 2^64.  Counter-driven trip
 * matches the (x & 7) + 1 recipe used by all working data-bound
 * samples.
 */
#include <stdio.h>
#include <stdint.h>

enum SqVmPc {
    SQ_INIT_ALL = 0,
    SQ_CHECK    = 1,
    SQ_BODY     = 2,
    SQ_INC      = 3,
    SQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_squareadd64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SQ_INIT_ALL;

    while (1) {
        if (pc == SQ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = SQ_CHECK;
        } else if (pc == SQ_CHECK) {
            pc = (i < n) ? SQ_BODY : SQ_HALT;
        } else if (pc == SQ_BODY) {
            r = r * r + i;
            pc = SQ_INC;
        } else if (pc == SQ_INC) {
            i = i + 1ull;
            pc = SQ_CHECK;
        } else if (pc == SQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_squareadd64(7)=%llu\n",
           (unsigned long long)vm_squareadd64_loop_target(7ull));
    return 0;
}
```
