# vm_digitsum_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_digitsum_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_digitsum_loop.ll`
- **Symbol:** `vm_digitsum_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_digitsum_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_digitsum_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | n=1 |
| 3 | RCX=9 | 9 | 9 | 9 | yes | n=9: single digit |
| 4 | RCX=10 | 1 | 1 | 1 | yes | n=10: 1+0 |
| 5 | RCX=42 | 6 | 6 | 6 | yes | n=42: 4+2 |
| 6 | RCX=99 | 18 | 18 | 18 | yes | n=99: 9+9 |
| 7 | RCX=255 | 12 | 12 | 12 | yes | n=255: 2+5+5 |
| 8 | RCX=1234 | 10 | 10 | 10 | yes | n=1234: 1+2+3+4 |
| 9 | RCX=9999 | 36 | 36 | 36 | yes | n=9999: 4*9 |
| 10 | RCX=65535 | 24 | 24 | 24 | yes | n=65535: 6+5+5+3+5 |
| 11 | RCX=65536 | 0 | 0 | 0 | yes | n=0 again (mask drops bit 16) |
| 12 | RCX=12345 | 15 | 15 | 15 | yes | n=12345: 1+2+3+4+5 |

## Source

```c
/* PC-state VM that sums the decimal digits of a symbolic input.
 * Lift target: vm_digitsum_loop_target.
 * Goal: cover a non-counted loop terminating on `n != 0`, with both
 * integer divide and modulo by 10 (non-power-of-2 divisor) in the body.
 * Distinct from vm_gcd_loop (different recurrence: n /= 10 vs Euclidean)
 * and vm_powermod_loop (smaller mod constant 13 with shift-driven loop).
 */
#include <stdio.h>

enum DsVmPc {
    DS_LOAD     = 0,
    DS_INIT     = 1,
    DS_CHECK    = 2,
    DS_BODY_DIG = 3,
    DS_BODY_ADD = 4,
    DS_BODY_DIV = 5,
    DS_HALT     = 6,
};

__declspec(noinline)
int vm_digitsum_loop_target(int x) {
    int n     = 0;
    int sum   = 0;
    int digit = 0;
    int pc    = DS_LOAD;

    while (1) {
        if (pc == DS_LOAD) {
            n = x & 0xFFFF;
            sum = 0;
            pc = DS_INIT;
        } else if (pc == DS_INIT) {
            pc = DS_CHECK;
        } else if (pc == DS_CHECK) {
            pc = (n > 0) ? DS_BODY_DIG : DS_HALT;
        } else if (pc == DS_BODY_DIG) {
            digit = n % 10;
            pc = DS_BODY_ADD;
        } else if (pc == DS_BODY_ADD) {
            sum = sum + digit;
            pc = DS_BODY_DIV;
        } else if (pc == DS_BODY_DIV) {
            n = n / 10;
            pc = DS_CHECK;
        } else if (pc == DS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_digitsum_loop(1234)=%d vm_digitsum_loop(65535)=%d\n",
           vm_digitsum_loop_target(1234), vm_digitsum_loop_target(65535));
    return 0;
}
```
