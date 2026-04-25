# vm_digitprod64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_digitprod64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_digitprod64_loop.ll`
- **Symbol:** `vm_digitprod64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_digitprod64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_digitprod64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: special-case 0 |
| 2 | RCX=5 | 5 | 5 | 5 | yes | x=5: single digit |
| 3 | RCX=12 | 2 | 2 | 2 | yes | x=12: 1*2 |
| 4 | RCX=99 | 81 | 81 | 81 | yes | x=99: 9*9 |
| 5 | RCX=100 | 0 | 0 | 0 | yes | x=100: contains 0 digit |
| 6 | RCX=123 | 6 | 6 | 6 | yes | x=123: 1*2*3 |
| 7 | RCX=999 | 729 | 729 | 729 | yes | x=999: 9^3 |
| 8 | RCX=255 | 50 | 50 | 50 | yes | x=255: 2*5*5 |
| 9 | RCX=999999999 | 387420489 | 387420489 | 387420489 | yes | x=10^9-1: 9^9 |
| 10 | RCX=51966 | 1620 | 1620 | 1620 | yes | x=0xCAFE=51966 dec |

## Source

```c
/* PC-state VM that computes the product of decimal digits of x.
 *   if (x == 0) return 0;
 *   p = 1;
 *   while (s) { p *= s % 10; s /= 10; }
 *   return p;
 * Variable trip = number of decimal digits.  Returns full uint64_t (low
 * bits dominate; any zero-digit collapses the product to 0).
 * Lift target: vm_digitprod64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (counts digits) and vm_base7sum64_loop
 * (digit SUM in base 7): exercises i64 mul-by-digit accumulator with
 * udiv-by-10 + urem-by-10 inside a data-dependent loop.  Any zero
 * digit forces immediate sticky 0 result.
 */
#include <stdio.h>
#include <stdint.h>

enum DpVmPc {
    DP_LOAD       = 0,
    DP_ZERO_CHECK = 1,
    DP_LOOP_CHECK = 2,
    DP_LOOP_BODY  = 3,
    DP_HALT       = 4,
};

__declspec(noinline)
uint64_t vm_digitprod64_loop_target(uint64_t x) {
    uint64_t s   = 0;
    uint64_t p   = 0;
    int      pc  = DP_LOAD;

    while (1) {
        if (pc == DP_LOAD) {
            s = x;
            p = 1ull;
            pc = DP_ZERO_CHECK;
        } else if (pc == DP_ZERO_CHECK) {
            if (s == 0ull) {
                p = 0ull;
                pc = DP_HALT;
            } else {
                pc = DP_LOOP_CHECK;
            }
        } else if (pc == DP_LOOP_CHECK) {
            pc = (s != 0ull) ? DP_LOOP_BODY : DP_HALT;
        } else if (pc == DP_LOOP_BODY) {
            p = p * (s % 10ull);
            s = s / 10ull;
            pc = DP_LOOP_CHECK;
        } else if (pc == DP_HALT) {
            return p;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_digitprod64(123)=%llu vm_digitprod64(999999999)=%llu\n",
           (unsigned long long)vm_digitprod64_loop_target(123ull),
           (unsigned long long)vm_digitprod64_loop_target(999999999ull));
    return 0;
}
```
