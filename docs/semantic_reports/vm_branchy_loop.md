# vm_branchy_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_branchy_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_branchy_loop.ll`
- **Symbol:** `vm_branchy_loop_target`
- **IR size:** 71 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=0: no iterations |
| 2 | RCX=1 | 0 | 0 | pass | limit=1: only i=0 (even) |
| 3 | RCX=2 | 1 | 1 | pass | limit=2: i=1 is odd |
| 4 | RCX=5 | 2 | 2 | pass | limit=5: odds {1,3} |
| 5 | RCX=10 | 5 | 5 | pass | limit=10: odds {1,3,5,7,9} |
| 6 | RCX=15 | 7 | 7 | pass | limit=15: odds 1..13 |
| 7 | RCX=16 | 0 | 0 | pass | limit=0 (mask drops bit 4) |
| 8 | RCX=31 | 7 | 7 | pass | limit=15 again after mask |

## Source

```c
/* PC-state VM with a conditional branch inside the loop body.
 * Lift target: vm_branchy_loop_target.
 * Goal: keep a VM-shaped dispatcher with a real loop AND a data-dependent
 * branch in the loop body (parity test on the loop induction variable).
 * Counts how many odd values exist in [0, limit) where limit = x & 0xF.
 */
#include <stdio.h>

enum BranchVmPc {
    BV_INIT        = 0,
    BV_LOAD_LIMIT  = 1,
    BV_CHECK_LIMIT = 2,
    BV_TEST_PARITY = 3,
    BV_INC_COUNT   = 4,
    BV_INC_INDEX   = 5,
    BV_HALT        = 6,
};

__declspec(noinline)
int vm_branchy_loop_target(int x) {
    int i      = 0;
    int count  = 0;
    int limit  = 0;
    int parity = 0;
    int pc     = BV_LOAD_LIMIT;

    while (1) {
        if (pc == BV_LOAD_LIMIT) {
            i = 0;
            count = 0;
            limit = x & 0xF;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_CHECK_LIMIT) {
            pc = (i < limit) ? BV_TEST_PARITY : BV_HALT;
        } else if (pc == BV_TEST_PARITY) {
            parity = i & 1;
            pc = (parity != 0) ? BV_INC_COUNT : BV_INC_INDEX;
        } else if (pc == BV_INC_COUNT) {
            count = count + 1;
            pc = BV_INC_INDEX;
        } else if (pc == BV_INC_INDEX) {
            i = i + 1;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_branchy_loop(10)=%d vm_branchy_loop(15)=%d\n",
           vm_branchy_loop_target(10), vm_branchy_loop_target(15));
    return 0;
}
```
