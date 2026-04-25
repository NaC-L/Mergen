# vm_argmax_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_argmax_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_argmax_loop.ll`
- **Symbol:** `vm_argmax_loop_target`
- **IR size:** 156 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=1 |
| 2 | RCX=1 | 1 | 1 | pass | limit=2 |
| 3 | RCX=2 | 2 | 2 | pass | limit=3 |
| 4 | RCX=7 | 4 | 4 | pass | limit=8: max at i=4 |
| 5 | RCX=55 | 4 | 4 | pass | 0x37: limit=8 |
| 6 | RCX=170 | 2 | 2 | pass | 0xAA: limit=3, max at i=2 |
| 7 | RCX=196 | 1 | 1 | pass | 0xC4: limit=5, max at i=1 |
| 8 | RCX=255 | 0 | 0 | pass | 0xFF: limit=8, max at i=0 |
| 9 | RCX=256 | 0 | 0 | pass | limit=1 (mask drops bit 8) |
| 10 | RCX=4660 | 4 | 4 | pass | 0x1234: limit=5 |
| 11 | RCX=65244 | 1 | 1 | pass | 0xFEDC: limit=5, max at i=1 |

## Source

```c
/* PC-state VM that finds the INDEX of the max element in a symbolic-content
 * stack array.
 * Lift target: vm_argmax_loop_target.
 * Goal: cover a comparison-driven loop that tracks TWO co-related state vars
 * (current best value AND its index) where both update together when the
 * predicate is true.  Distinct from vm_minarray_loop (only tracks value, not
 * index).  Initial values come from data[0]/idx=0 written on the entry path
 * to keep the lifter's pseudo-stack promotion happy.
 */
#include <stdio.h>

enum AmVmPc {
    AM_LOAD       = 0,
    AM_INIT_FILL  = 1,
    AM_FILL_CHECK = 2,
    AM_FILL_BODY  = 3,
    AM_FILL_INC   = 4,
    AM_INIT_BEST  = 5,
    AM_SCAN_CHECK = 6,
    AM_SCAN_LOAD  = 7,
    AM_SCAN_TEST  = 8,
    AM_SCAN_UPD   = 9,
    AM_SCAN_INC   = 10,
    AM_HALT       = 11,
};

__declspec(noinline)
int vm_argmax_loop_target(int x) {
    int data[8];
    int limit  = 0;
    int idx    = 0;
    int best   = 0;
    int best_i = 0;
    int elt    = 0;
    int pc     = AM_LOAD;

    while (1) {
        if (pc == AM_LOAD) {
            limit = (x & 7) + 1;
            pc = AM_INIT_FILL;
        } else if (pc == AM_INIT_FILL) {
            idx = 0;
            pc = AM_FILL_CHECK;
        } else if (pc == AM_FILL_CHECK) {
            pc = (idx < limit) ? AM_FILL_BODY : AM_INIT_BEST;
        } else if (pc == AM_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x35)) & 0xFF;
            pc = AM_FILL_INC;
        } else if (pc == AM_FILL_INC) {
            idx = idx + 1;
            pc = AM_FILL_CHECK;
        } else if (pc == AM_INIT_BEST) {
            best = data[0];
            best_i = 0;
            idx = 1;
            pc = AM_SCAN_CHECK;
        } else if (pc == AM_SCAN_CHECK) {
            pc = (idx < limit) ? AM_SCAN_LOAD : AM_HALT;
        } else if (pc == AM_SCAN_LOAD) {
            elt = data[idx];
            pc = AM_SCAN_TEST;
        } else if (pc == AM_SCAN_TEST) {
            pc = (elt > best) ? AM_SCAN_UPD : AM_SCAN_INC;
        } else if (pc == AM_SCAN_UPD) {
            best = elt;
            best_i = idx;
            pc = AM_SCAN_INC;
        } else if (pc == AM_SCAN_INC) {
            idx = idx + 1;
            pc = AM_SCAN_CHECK;
        } else if (pc == AM_HALT) {
            return best_i;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_argmax_loop(0x37)=%d vm_argmax_loop(0xFEDC)=%d\n",
           vm_argmax_loop_target(0x37), vm_argmax_loop_target(0xFEDC));
    return 0;
}
```
