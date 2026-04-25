# vm_factorial_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_factorial_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_factorial_loop.ll`
- **Symbol:** `vm_factorial_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_factorial_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_factorial_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | limit=0: empty product |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=1: 1! |
| 3 | RCX=2 | 2 | 2 | 2 | yes | limit=2: 2! |
| 4 | RCX=3 | 6 | 6 | 6 | yes | limit=3: 3! |
| 5 | RCX=4 | 24 | 24 | 24 | yes | limit=4: 4! |
| 6 | RCX=5 | 120 | 120 | 120 | yes | limit=5: 5! |
| 7 | RCX=6 | 720 | 720 | 720 | yes | limit=6: 6! |
| 8 | RCX=7 | 5040 | 5040 | 5040 | yes | limit=7: 7! |
| 9 | RCX=8 | 1 | 1 | 1 | yes | limit=0 again (mask drops bit 3) |
| 10 | RCX=15 | 5040 | 5040 | 5040 | yes | limit=7 again after mask |

## Source

```c
/* PC-state VM that computes factorial via a multiplicative loop in VM state.
 * Lift target: vm_factorial_loop_target.
 * Goal: cover a multiplicative recurrence (acc *= i) instead of the additive
 * sum loops in the other VM samples. The loop bound is symbolic (limit = x & 7)
 * so the lifter cannot constant-fold the result.
 */
#include <stdio.h>

enum FactVmPc {
    FV_INIT       = 0,
    FV_LOAD_LIMIT = 1,
    FV_INIT_PROD  = 2,
    FV_INIT_INDEX = 3,
    FV_CHECK      = 4,
    FV_BODY_MUL   = 5,
    FV_BODY_INC   = 6,
    FV_HALT       = 7,
};

__declspec(noinline)
int vm_factorial_loop_target(int x) {
    int limit = 0;
    int prod  = 0;
    int i     = 0;
    int pc    = FV_INIT;

    while (1) {
        if (pc == FV_INIT) {
            pc = FV_LOAD_LIMIT;
        } else if (pc == FV_LOAD_LIMIT) {
            limit = x & 7;
            pc = FV_INIT_PROD;
        } else if (pc == FV_INIT_PROD) {
            prod = 1;
            pc = FV_INIT_INDEX;
        } else if (pc == FV_INIT_INDEX) {
            i = 1;
            pc = FV_CHECK;
        } else if (pc == FV_CHECK) {
            pc = (i <= limit) ? FV_BODY_MUL : FV_HALT;
        } else if (pc == FV_BODY_MUL) {
            prod = prod * i;
            pc = FV_BODY_INC;
        } else if (pc == FV_BODY_INC) {
            i = i + 1;
            pc = FV_CHECK;
        } else if (pc == FV_HALT) {
            return prod;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_factorial_loop(5)=%d vm_factorial_loop(7)=%d\n",
           vm_factorial_loop_target(5), vm_factorial_loop_target(7));
    return 0;
}
```
