# vm_saturating_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_saturating_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_saturating_loop.ll`
- **Symbol:** `vm_saturating_loop_target`
- **IR size:** 74 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | n=0 |
| 2 | RCX=1 | 0 | 0 | pass | n=1 |
| 3 | RCX=2 | 1 | 1 | pass | n=2 |
| 4 | RCX=5 | 10 | 10 | pass | n=5: 0+1+2+3+4 |
| 5 | RCX=10 | 45 | 45 | pass | n=10: 0..9 sum 45 |
| 6 | RCX=14 | 91 | 91 | pass | n=14: just below clamp |
| 7 | RCX=15 | 100 | 100 | pass | n=15: 105 -> clamp |
| 8 | RCX=20 | 100 | 100 | pass | n=20: clamped |
| 9 | RCX=128 | 100 | 100 | pass | n=128: clamped |
| 10 | RCX=255 | 100 | 100 | pass | n=255: clamped |

## Source

```c
/* PC-state VM running a counted sum loop with saturation clamp.
 * Lift target: vm_saturating_loop_target.
 * Goal: cover a loop body that performs an add followed by a value-clamp
 * (select on overflow), distinct from the pure additive sum loops which
 * grow unbounded.  Trip count n = x & 0xFF spans the full clamp boundary.
 */
#include <stdio.h>

enum SatVmPc {
    ST_LOAD     = 0,
    ST_INIT     = 1,
    ST_CHECK    = 2,
    ST_BODY_ADD = 3,
    ST_BODY_CLAMP = 4,
    ST_BODY_INC = 5,
    ST_HALT     = 6,
};

__declspec(noinline)
int vm_saturating_loop_target(int x) {
    int n   = 0;
    int i   = 0;
    int sum = 0;
    int pc  = ST_LOAD;

    while (1) {
        if (pc == ST_LOAD) {
            n = x & 0xFF;
            i = 0;
            sum = 0;
            pc = ST_INIT;
        } else if (pc == ST_INIT) {
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY_ADD : ST_HALT;
        } else if (pc == ST_BODY_ADD) {
            sum = sum + i;
            pc = ST_BODY_CLAMP;
        } else if (pc == ST_BODY_CLAMP) {
            if (sum > 100) {
                sum = 100;
            }
            pc = ST_BODY_INC;
        } else if (pc == ST_BODY_INC) {
            i = i + 1;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_saturating_loop(10)=%d vm_saturating_loop(20)=%d\n",
           vm_saturating_loop_target(10), vm_saturating_loop_target(20));
    return 0;
}
```
