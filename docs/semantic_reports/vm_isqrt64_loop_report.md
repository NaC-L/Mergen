# vm_isqrt64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_isqrt64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_isqrt64_loop.ll`
- **Symbol:** `vm_isqrt64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_isqrt64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_isqrt64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | isqrt(0)=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | isqrt(1)=1 |
| 3 | RCX=4 | 2 | 2 | 2 | yes | isqrt(4)=2 |
| 4 | RCX=10 | 3 | 3 | 3 | yes | isqrt(10)=3 (floor) |
| 5 | RCX=10000 | 100 | 100 | 100 | yes | isqrt(10000)=100 |
| 6 | RCX=100000000 | 10000 | 10000 | 10000 | yes | isqrt(1e8)=10000 |
| 7 | RCX=18446744073709551615 | 4294967295 | 4294967295 | 4294967295 | yes | isqrt(max u64) = 2^32-1 |
| 8 | RCX=4611686018427387904 | 2147483648 | 2147483648 | 2147483648 | yes | isqrt(2^62) = 2^31 |
| 9 | RCX=4294967296 | 65536 | 65536 | 65536 | yes | isqrt(2^32) = 2^16 |
| 10 | RCX=12345678901234 | 3513641 | 3513641 | 3513641 | yes | isqrt(1.234e13) |

## Source

```c
/* PC-state VM running the bit-by-bit integer-square-root algorithm on
 * full uint64_t.  Fixed-trip 32-iteration loop (bit walks from 2^62
 * down to 2^0 in steps of 4).  Returns floor(sqrt(x)) as full uint64_t.
 *
 *   res = 0; bit = 1<<62;
 *   while (bit) {
 *     if (x >= res + bit) { x -= res + bit; res = (res >> 1) + bit; }
 *     else                 { res >>= 1; }
 *     bit >>= 2;
 *   }
 *   return res;
 *
 * Lift target: vm_isqrt64_loop_target.
 *
 * Distinct from vm_isqrt_loop (i32 isqrt): exercises the same shape on
 * full 64-bit state with a 32-trip fixed-bound loop containing branchy
 * accumulator updates.
 */
#include <stdio.h>
#include <stdint.h>

enum SqVmPc {
    SQ_LOAD       = 0,
    SQ_LOOP_CHECK = 1,
    SQ_LOOP_BODY  = 2,
    SQ_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_isqrt64_loop_target(uint64_t x) {
    uint64_t state = 0;
    uint64_t res   = 0;
    uint64_t bit   = 0;
    int      pc    = SQ_LOAD;

    while (1) {
        if (pc == SQ_LOAD) {
            state = x;
            res   = 0ull;
            bit   = 1ull << 62;
            pc = SQ_LOOP_CHECK;
        } else if (pc == SQ_LOOP_CHECK) {
            pc = (bit != 0ull) ? SQ_LOOP_BODY : SQ_HALT;
        } else if (pc == SQ_LOOP_BODY) {
            if (state >= res + bit) {
                state = state - (res + bit);
                res   = (res >> 1) + bit;
            } else {
                res = res >> 1;
            }
            bit = bit >> 2;
            pc = SQ_LOOP_CHECK;
        } else if (pc == SQ_HALT) {
            return res;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_isqrt64(10000)=%llu vm_isqrt64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_isqrt64_loop_target(10000ull),
           (unsigned long long)vm_isqrt64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
