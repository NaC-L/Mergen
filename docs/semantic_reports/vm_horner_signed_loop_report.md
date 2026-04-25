# vm_horner_signed_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_horner_signed_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_horner_signed_loop.ll`
- **Symbol:** `vm_horner_signed_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_horner_signed_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_horner_signed_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 4294967294 | 4294967294 | 4294967294 | yes | t=1: -2 unsigned |
| 2 | RCX=1 | 2 | 2 | 2 | yes | t=2: 2 |
| 3 | RCX=2 | 14 | 14 | 14 | yes | t=3: 14 |
| 4 | RCX=3 | 40 | 40 | 40 | yes | t=4: 40 |
| 5 | RCX=4 | 86 | 86 | 86 | yes | t=5: 86 |
| 6 | RCX=5 | 158 | 158 | 158 | yes | t=6: 158 |
| 7 | RCX=6 | 262 | 262 | 262 | yes | t=7: 262 |
| 8 | RCX=7 | 404 | 404 | 404 | yes | t=8: 404 |
| 9 | RCX=8 | 4294967294 | 4294967294 | 4294967294 | yes | t=1 again (mask drops bit 3) |
| 10 | RCX=15 | 404 | 404 | 404 | yes | t=8 again after mask |

## Source

```c
/* PC-state VM evaluating a polynomial with signed coefficients via Horner's
 * method.
 * Lift target: vm_horner_signed_loop_target.
 * Goal: cover signed multiply-and-add inside a loop where the coefficient
 * array contains negative values.  Distinct from vm_polynomial_loop (all
 * positive coefficients): tests sign extension of small constants stored
 * to a stack array and consumed by mul.  p(t) = t^3 - 2t^2 + 3t - 4.
 */
#include <stdio.h>

enum HsVmPc {
    HS_LOAD       = 0,
    HS_INIT       = 1,
    HS_INIT_COEF  = 2,
    HS_CHECK      = 3,
    HS_BODY_LOAD  = 4,
    HS_BODY_MUL   = 5,
    HS_BODY_ADD   = 6,
    HS_BODY_INC   = 7,
    HS_HALT       = 8,
};

__declspec(noinline)
int vm_horner_signed_loop_target(int x) {
    int coef[4];
    int t      = 0;
    int i      = 0;
    int result = 0;
    int c      = 0;
    int prod   = 0;
    int pc     = HS_LOAD;

    while (1) {
        if (pc == HS_LOAD) {
            t = (x & 7) + 1;
            i = 0;
            result = 0;
            pc = HS_INIT_COEF;
        } else if (pc == HS_INIT_COEF) {
            coef[0] = 1;
            coef[1] = -2;
            coef[2] = 3;
            coef[3] = -4;
            pc = HS_CHECK;
        } else if (pc == HS_CHECK) {
            pc = (i < 4) ? HS_BODY_LOAD : HS_HALT;
        } else if (pc == HS_BODY_LOAD) {
            c = coef[i];
            pc = HS_BODY_MUL;
        } else if (pc == HS_BODY_MUL) {
            prod = result * t;
            pc = HS_BODY_ADD;
        } else if (pc == HS_BODY_ADD) {
            result = prod + c;
            pc = HS_BODY_INC;
        } else if (pc == HS_BODY_INC) {
            i = i + 1;
            pc = HS_CHECK;
        } else if (pc == HS_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_horner_signed_loop(0)=%d vm_horner_signed_loop(7)=%d\n",
           vm_horner_signed_loop_target(0), vm_horner_signed_loop_target(7));
    return 0;
}
```
