# vm_collatz_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_collatz_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_collatz_loop.ll`
- **Symbol:** `vm_collatz_loop_target`
- **IR size:** 78 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | n=1: already done |
| 2 | RCX=1 | 1 | 1 | pass | n=2: 2->1 |
| 3 | RCX=2 | 7 | 7 | pass | n=3: 7 steps |
| 4 | RCX=3 | 2 | 2 | pass | n=4: 4->2->1 |
| 5 | RCX=4 | 5 | 5 | pass | n=5: 5 steps |
| 6 | RCX=5 | 8 | 8 | pass | n=6: 8 steps |
| 7 | RCX=6 | 16 | 16 | pass | n=7: 16 steps |
| 8 | RCX=7 | 3 | 3 | pass | n=8: 3 steps |

## Source

```c
/* PC-state VM running a Collatz step counter.
 * Lift target: vm_collatz_loop_target.
 * Goal: data-dependent control flow inside the VM loop body (parity test
 * picks the divide-by-two or 3n+1 handler).  The loop terminates when n
 * reaches 1 - the iteration count itself is the return value.  Input is
 * mapped to (x & 7) + 1 so n stays in [1, 8] and the trip count is bounded
 * (max 16 for n=7) while remaining symbolic.
 */
#include <stdio.h>

enum CollatzVmPc {
    CV_INIT       = 0,
    CV_LOAD_N     = 1,
    CV_CHECK_DONE = 2,
    CV_TEST_PARITY= 3,
    CV_EVEN_HALVE = 4,
    CV_ODD_3N1    = 5,
    CV_INC_STEPS  = 6,
    CV_HALT       = 7,
};

__declspec(noinline)
int vm_collatz_loop_target(int x) {
    int n     = 0;
    int steps = 0;
    int pc    = CV_LOAD_N;

    while (1) {
        if (pc == CV_LOAD_N) {
            n = (x & 7) + 1;
            pc = CV_CHECK_DONE;
        } else if (pc == CV_CHECK_DONE) {
            pc = (n != 1) ? CV_TEST_PARITY : CV_HALT;
        } else if (pc == CV_TEST_PARITY) {
            pc = ((n & 1) == 0) ? CV_EVEN_HALVE : CV_ODD_3N1;
        } else if (pc == CV_EVEN_HALVE) {
            n = n / 2;
            pc = CV_INC_STEPS;
        } else if (pc == CV_ODD_3N1) {
            n = 3 * n + 1;
            pc = CV_INC_STEPS;
        } else if (pc == CV_INC_STEPS) {
            steps = steps + 1;
            pc = CV_CHECK_DONE;
        } else if (pc == CV_HALT) {
            return steps;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_collatz_loop(2)=%d vm_collatz_loop(6)=%d\n",
           vm_collatz_loop_target(2), vm_collatz_loop_target(6));
    return 0;
}
```
