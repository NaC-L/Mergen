# vm_dual_counter_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_dual_counter_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dual_counter_loop.ll`
- **Symbol:** `vm_dual_counter_loop_target`
- **IR size:** 97 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=0 |
| 2 | RCX=1 | 100 | 100 | pass | limit=1: 1 even, 0 odd |
| 3 | RCX=2 | 101 | 101 | pass | limit=2: 1 even, 1 odd |
| 4 | RCX=5 | 302 | 302 | pass | limit=5: 3 even, 2 odd |
| 5 | RCX=8 | 404 | 404 | pass | limit=8: 4 even, 4 odd |
| 6 | RCX=10 | 505 | 505 | pass | limit=10: 5 even, 5 odd |
| 7 | RCX=15 | 807 | 807 | pass | limit=15: 8 even, 7 odd |
| 8 | RCX=16 | 0 | 0 | pass | limit=0 again (mask drops bit 4) |

## Source

```c
/* PC-state VM whose loop body updates two independent counters per iteration.
 * Lift target: vm_dual_counter_loop_target.
 * Goal: cover a loop where the parity-driven branch sends control to one of
 * two distinct increment handlers and merges back, so the lifter must
 * preserve two independent phi nodes inside the loop body.  Returns
 * even_count * 100 + odd_count for limit = x & 0xF.
 */
#include <stdio.h>

enum DualVmPc {
    DV_INIT       = 0,
    DV_LOAD_LIMIT = 1,
    DV_INIT_CTRS  = 2,
    DV_INIT_IDX   = 3,
    DV_CHECK      = 4,
    DV_TEST_PAR   = 5,
    DV_INC_EVEN   = 6,
    DV_INC_ODD    = 7,
    DV_INC_IDX    = 8,
    DV_PACK       = 9,
    DV_HALT       = 10,
};

__declspec(noinline)
int vm_dual_counter_loop_target(int x) {
    int limit  = 0;
    int idx    = 0;
    int evens  = 0;
    int odds   = 0;
    int result = 0;
    int pc     = DV_INIT;

    while (1) {
        if (pc == DV_INIT) {
            pc = DV_LOAD_LIMIT;
        } else if (pc == DV_LOAD_LIMIT) {
            limit = x & 0xF;
            pc = DV_INIT_CTRS;
        } else if (pc == DV_INIT_CTRS) {
            evens = 0;
            odds = 0;
            pc = DV_INIT_IDX;
        } else if (pc == DV_INIT_IDX) {
            idx = 0;
            pc = DV_CHECK;
        } else if (pc == DV_CHECK) {
            pc = (idx < limit) ? DV_TEST_PAR : DV_PACK;
        } else if (pc == DV_TEST_PAR) {
            pc = ((idx & 1) == 0) ? DV_INC_EVEN : DV_INC_ODD;
        } else if (pc == DV_INC_EVEN) {
            evens = evens + 1;
            pc = DV_INC_IDX;
        } else if (pc == DV_INC_ODD) {
            odds = odds + 1;
            pc = DV_INC_IDX;
        } else if (pc == DV_INC_IDX) {
            idx = idx + 1;
            pc = DV_CHECK;
        } else if (pc == DV_PACK) {
            result = evens * 100 + odds;
            pc = DV_HALT;
        } else if (pc == DV_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dual_counter_loop(10)=%d vm_dual_counter_loop(15)=%d\n",
           vm_dual_counter_loop_target(10), vm_dual_counter_loop_target(15));
    return 0;
}
```
