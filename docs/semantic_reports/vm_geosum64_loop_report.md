# vm_geosum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_geosum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_geosum64_loop.ll`
- **Symbol:** `vm_geosum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_geosum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_geosum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | n=1: 3^0=1 |
| 2 | RCX=1 | 4 | 4 | 4 | yes | n=2: 1+3=4 |
| 3 | RCX=2 | 13 | 13 | 13 | yes | n=3: 1+3+9=13 |
| 4 | RCX=3 | 40 | 40 | 40 | yes | n=4: 40 |
| 5 | RCX=7 | 3280 | 3280 | 3280 | yes | n=8: (3^8-1)/2=3280 |
| 6 | RCX=8 | 9841 | 9841 | 9841 | yes | n=9 |
| 7 | RCX=14 | 7174453 | 7174453 | 7174453 | yes | n=15 |
| 8 | RCX=15 | 21523360 | 21523360 | 21523360 | yes | n=16: (3^16-1)/2 max trip |
| 9 | RCX=16 | 1 | 1 | 1 | yes | low-nibble wraps: same as x=0 |
| 10 | RCX=18446744073709551615 | 21523360 | 21523360 | 21523360 | yes | max u64: low nibble=15 |

## Source

```c
/* PC-state VM that accumulates a geometric series 1 + 3 + 9 + ... + 3^(n-1)
 * over n = (x & 15) + 1 iterations, with everything in u64 arithmetic
 * (matters once 3^k overflows beyond n=15).
 *
 *   n = (x & 15) + 1;
 *   r = 0; p = 1;
 *   while (n) { r += p; p *= 3; n--; }
 *   return r;
 *
 * Lift target: vm_geosum64_loop_target.
 *
 * Distinct from vm_fibonacci_loop (additive a,b two-state) and from
 * vm_powmod64 (modular exponentiation).  Two-state (r, p) where p is
 * MULTIPLIED by a constant each iteration and r accumulates p.  Same
 * counter-bound shape as fibonacci_loop so the lifter generalizes the
 * loop, but the body exercises i64 multiply-by-3 and add chained.
 */
#include <stdio.h>
#include <stdint.h>

enum GsVmPc {
    GS_LOAD_N    = 0,
    GS_INIT_REGS = 1,
    GS_CHECK     = 2,
    GS_ACC       = 3,
    GS_SCALE     = 4,
    GS_DEC       = 5,
    GS_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_geosum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t r = 0;
    uint64_t p = 0;
    int      pc = GS_LOAD_N;

    while (1) {
        if (pc == GS_LOAD_N) {
            n = (x & 15ull) + 1ull;
            pc = GS_INIT_REGS;
        } else if (pc == GS_INIT_REGS) {
            r = 0ull;
            p = 1ull;
            pc = GS_CHECK;
        } else if (pc == GS_CHECK) {
            pc = (n > 0ull) ? GS_ACC : GS_HALT;
        } else if (pc == GS_ACC) {
            r = r + p;
            pc = GS_SCALE;
        } else if (pc == GS_SCALE) {
            p = p * 3ull;
            pc = GS_DEC;
        } else if (pc == GS_DEC) {
            n = n - 1ull;
            pc = GS_CHECK;
        } else if (pc == GS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_geosum64(7)=%llu vm_geosum64(15)=%llu\n",
           (unsigned long long)vm_geosum64_loop_target(7ull),
           (unsigned long long)vm_geosum64_loop_target(15ull));
    return 0;
}
```
