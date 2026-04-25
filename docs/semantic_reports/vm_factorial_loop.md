# vm_factorial_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_factorial_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_factorial_loop.ll`
- **Symbol:** `vm_factorial_loop_target`
- **IR size:** 34 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | limit=0: empty product |
| 2 | RCX=1 | 1 | 1 | pass | limit=1: 1! |
| 3 | RCX=2 | 2 | 2 | pass | limit=2: 2! |
| 4 | RCX=3 | 6 | 6 | pass | limit=3: 3! |
| 5 | RCX=4 | 24 | 24 | pass | limit=4: 4! |
| 6 | RCX=5 | 120 | 120 | pass | limit=5: 5! |
| 7 | RCX=6 | 720 | 720 | pass | limit=6: 6! |
| 8 | RCX=7 | 5040 | 5040 | pass | limit=7: 7! |
| 9 | RCX=8 | 1 | 1 | pass | limit=0 again (mask drops bit 3) |
| 10 | RCX=15 | 5040 | 5040 | pass | limit=7 again after mask |

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
