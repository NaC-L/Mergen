# vm_trailzeros_factorial64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_trailzeros_factorial64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_trailzeros_factorial64_loop.ll`
- **Symbol:** `vm_trailzeros_factorial64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_trailzeros_factorial64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_trailzeros_factorial64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=0: 0 trailing zeros (0!=1) |
| 2 | RCX=1 | 0 | 0 | 0 | yes | n=1: 1!=1 |
| 3 | RCX=4 | 0 | 0 | 0 | yes | n=4: 4!=24, 0 trailing zeros |
| 4 | RCX=5 | 1 | 1 | 1 | yes | n=5: 5!=120, 1 trailing zero |
| 5 | RCX=10 | 2 | 2 | 2 | yes | n=10: 10! has 2 |
| 6 | RCX=24 | 4 | 4 | 4 | yes | n=24: 24! has 4 |
| 7 | RCX=25 | 6 | 6 | 6 | yes | n=25: jump from 4 to 6 at 25 |
| 8 | RCX=100 | 24 | 24 | 24 | yes | n=100: 100! has 24 |
| 9 | RCX=1000 | 249 | 249 | 249 | yes | n=1000: 1000! has 249 |
| 10 | RCX=18446744073709551615 | 4611686018427387890 | 4611686018427387890 | 4611686018427387890 | yes | max u64: ~floor(n/4) |

## Source

```c
/* PC-state VM that computes the number of trailing zeros in n!  via
 * Legendre's formula:  c = floor(n/5) + floor(n/25) + floor(n/125) + ...
 *
 *   s = n; c = 0;
 *   while (s) { s /= 5; c += s; }
 *   return c;
 *
 * Variable trip = log_5(n).  Returns full uint64_t.
 * Lift target: vm_trailzeros_factorial64_loop_target.
 *
 * Distinct from vm_decsum64_loop / vm_revdecimal64_loop (divide-by-10)
 * and vm_digitprod64_loop (multiply digits).  Tests udiv-by-5
 * (different magic number) inside data-dependent loop where each
 * iteration adds the running quotient (not the remainder) to the
 * accumulator.  This is the classical Legendre trailing-zero formula.
 */
#include <stdio.h>
#include <stdint.h>

enum TzVmPc {
    TZ_LOAD       = 0,
    TZ_LOOP_CHECK = 1,
    TZ_LOOP_BODY  = 2,
    TZ_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_trailzeros_factorial64_loop_target(uint64_t n) {
    uint64_t s = 0;
    uint64_t c = 0;
    int      pc = TZ_LOAD;

    while (1) {
        if (pc == TZ_LOAD) {
            s = n;
            c = 0ull;
            pc = TZ_LOOP_CHECK;
        } else if (pc == TZ_LOOP_CHECK) {
            pc = (s != 0ull) ? TZ_LOOP_BODY : TZ_HALT;
        } else if (pc == TZ_LOOP_BODY) {
            s = s / 5ull;
            c = c + s;
            pc = TZ_LOOP_CHECK;
        } else if (pc == TZ_HALT) {
            return c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_tz_fact(100)=%llu vm_tz_fact(1000000)=%llu\n",
           (unsigned long long)vm_trailzeros_factorial64_loop_target(100ull),
           (unsigned long long)vm_trailzeros_factorial64_loop_target(1000000ull));
    return 0;
}
```
