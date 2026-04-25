# vm_isqrt_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 15/15 equivalent
- **Source:** `testcases/rewrite_smoke/vm_isqrt_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_isqrt_loop.ll`
- **Symbol:** `vm_isqrt_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_isqrt_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_isqrt_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | isqrt(0) |
| 2 | RCX=1 | 1 | 1 | 1 | yes | isqrt(1) |
| 3 | RCX=2 | 1 | 1 | 1 | yes | isqrt(2) |
| 4 | RCX=4 | 2 | 2 | 2 | yes | isqrt(4) |
| 5 | RCX=9 | 3 | 3 | 3 | yes | isqrt(9) |
| 6 | RCX=10 | 3 | 3 | 3 | yes | isqrt(10) |
| 7 | RCX=16 | 4 | 4 | 4 | yes | isqrt(16) |
| 8 | RCX=25 | 5 | 5 | 5 | yes | isqrt(25) |
| 9 | RCX=100 | 10 | 10 | 10 | yes | isqrt(100) |
| 10 | RCX=255 | 15 | 15 | 15 | yes | isqrt(255) |
| 11 | RCX=256 | 16 | 16 | 16 | yes | isqrt(256) |
| 12 | RCX=1000 | 31 | 31 | 31 | yes | isqrt(1000) |
| 13 | RCX=9999 | 99 | 99 | 99 | yes | isqrt(9999) |
| 14 | RCX=65535 | 255 | 255 | 255 | yes | isqrt(65535) |
| 15 | RCX=65536 | 0 | 0 | 0 | yes | isqrt(0) again (mask drops bit 16) |

## Source

```c
/* PC-state VM running Newton's method for integer square root.
 * Lift target: vm_isqrt_loop_target.
 * Goal: cover a non-counted loop whose body divides by a *loop-variable*
 * (`n / a`), distinct from vm_digitsum_loop (constant divisor 10) and
 * vm_gcd_loop (modulo by loop variable but no division of a different
 * symbolic value). Termination uses a < b strict-decrease check.
 */
#include <stdio.h>

enum SqrtVmPc {
    SQ_LOAD       = 0,
    SQ_INIT       = 1,
    SQ_CHECK      = 2,
    SQ_BODY_DIV   = 3,
    SQ_BODY_SUM   = 4,
    SQ_BODY_HALF  = 5,
    SQ_BODY_SHIFT = 6,
    SQ_HALT       = 7,
};

__declspec(noinline)
int vm_isqrt_loop_target(int x) {
    int n   = 0;
    int a   = 0;
    int b   = 0;
    int q   = 0;
    int sum = 0;
    int pc  = SQ_LOAD;

    while (1) {
        if (pc == SQ_LOAD) {
            n = x & 0xFFFF;
            a = n;
            b = (n + 1) / 2;
            pc = SQ_CHECK;
        } else if (pc == SQ_CHECK) {
            pc = (b < a) ? SQ_BODY_DIV : SQ_HALT;
        } else if (pc == SQ_BODY_DIV) {
            a = b;
            q = n / a;
            pc = SQ_BODY_SUM;
        } else if (pc == SQ_BODY_SUM) {
            sum = a + q;
            pc = SQ_BODY_HALF;
        } else if (pc == SQ_BODY_HALF) {
            b = sum / 2;
            pc = SQ_CHECK;
        } else if (pc == SQ_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_isqrt_loop(100)=%d vm_isqrt_loop(65535)=%d\n",
           vm_isqrt_loop_target(100), vm_isqrt_loop_target(65535));
    return 0;
}
```
