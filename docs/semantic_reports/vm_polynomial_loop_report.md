# vm_polynomial_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_polynomial_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_polynomial_loop.ll`
- **Symbol:** `vm_polynomial_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_polynomial_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_polynomial_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 10 | 10 | 10 | yes | t=1: p(1)=10 |
| 2 | RCX=1 | 26 | 26 | 26 | yes | t=2: p(2)=26 |
| 3 | RCX=2 | 58 | 58 | 58 | yes | t=3: p(3)=58 |
| 4 | RCX=3 | 112 | 112 | 112 | yes | t=4: p(4)=112 |
| 5 | RCX=4 | 194 | 194 | 194 | yes | t=5: p(5)=194 |
| 6 | RCX=5 | 310 | 310 | 310 | yes | t=6: p(6)=310 |
| 7 | RCX=6 | 466 | 466 | 466 | yes | t=7: p(7)=466 |
| 8 | RCX=7 | 668 | 668 | 668 | yes | t=8: p(8)=668 |
| 9 | RCX=8 | 10 | 10 | 10 | yes | t=1 again (mask drops bit 3) |
| 10 | RCX=15 | 668 | 668 | 668 | yes | t=8 again after mask |

## Source

```c
/* PC-state VM evaluating a fixed polynomial via Horner's method.
 * Lift target: vm_polynomial_loop_target.
 * Goal: cover a loop body that does multiply-then-add against a runtime-
 * indexed coefficient array on the stack, exercising the same kind of
 * stack-array indexed load as vm_dispatch_table_loop but where the load
 * feeds an arithmetic accumulator rather than the dispatcher PC.
 * Computes p(t) = t^3 + 2t^2 + 3t + 4 with t = (x & 7) + 1.
 */
#include <stdio.h>

enum PolyVmPc {
    PL_LOAD       = 0,
    PL_INIT       = 1,
    PL_INIT_COEF  = 2,
    PL_CHECK      = 3,
    PL_BODY_LOAD  = 4,
    PL_BODY_MUL   = 5,
    PL_BODY_ADD   = 6,
    PL_BODY_INC   = 7,
    PL_HALT       = 8,
};

__declspec(noinline)
int vm_polynomial_loop_target(int x) {
    int coef[4];
    int t      = 0;
    int i      = 0;
    int result = 0;
    int c      = 0;
    int prod   = 0;
    int pc     = PL_LOAD;

    while (1) {
        if (pc == PL_LOAD) {
            t = (x & 7) + 1;
            i = 0;
            result = 0;
            pc = PL_INIT_COEF;
        } else if (pc == PL_INIT_COEF) {
            coef[0] = 1;
            coef[1] = 2;
            coef[2] = 3;
            coef[3] = 4;
            pc = PL_CHECK;
        } else if (pc == PL_CHECK) {
            pc = (i < 4) ? PL_BODY_LOAD : PL_HALT;
        } else if (pc == PL_BODY_LOAD) {
            c = coef[i];
            pc = PL_BODY_MUL;
        } else if (pc == PL_BODY_MUL) {
            prod = result * t;
            pc = PL_BODY_ADD;
        } else if (pc == PL_BODY_ADD) {
            result = prod + c;
            pc = PL_BODY_INC;
        } else if (pc == PL_BODY_INC) {
            i = i + 1;
            pc = PL_CHECK;
        } else if (pc == PL_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_polynomial_loop(2)=%d vm_polynomial_loop(7)=%d\n",
           vm_polynomial_loop_target(2), vm_polynomial_loop_target(7));
    return 0;
}
```
