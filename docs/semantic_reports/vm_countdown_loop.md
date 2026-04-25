# vm_countdown_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_countdown_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_countdown_loop.ll`
- **Symbol:** `vm_countdown_loop_target`
- **IR size:** 32 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | count=0: empty sum |
| 2 | RCX=1 | 1 | 1 | pass | count=1: T(1) |
| 3 | RCX=2 | 3 | 3 | pass | count=2: T(2) |
| 4 | RCX=5 | 15 | 15 | pass | count=5: T(5) |
| 5 | RCX=10 | 55 | 55 | pass | count=10: T(10) |
| 6 | RCX=15 | 120 | 120 | pass | count=15: T(15) |
| 7 | RCX=16 | 0 | 0 | pass | count=0 again (mask drops bit 4) |
| 8 | RCX=255 | 120 | 120 | pass | count=15 again after mask |

## Source

```c
/* PC-state VM with a reverse-induction counted loop.
 * Lift target: vm_countdown_loop_target.
 * Goal: exercise loop detection for a loop whose induction variable *decreases*
 * and whose bound is a symbolic countdown rather than a rising compare.
 * Computes the triangular number sum(1..n) where n = x & 0xF, but builds it
 * by counting down from n to 1 instead of up.
 */
#include <stdio.h>

enum CdVmPc {
    CD_INIT       = 0,
    CD_LOAD_COUNT = 1,
    CD_INIT_SUM   = 2,
    CD_CHECK      = 3,
    CD_BODY_ADD   = 4,
    CD_BODY_DEC   = 5,
    CD_HALT       = 6,
};

__declspec(noinline)
int vm_countdown_loop_target(int x) {
    int count = 0;
    int sum   = 0;
    int pc    = CD_INIT;

    while (1) {
        if (pc == CD_INIT) {
            pc = CD_LOAD_COUNT;
        } else if (pc == CD_LOAD_COUNT) {
            count = x & 0xF;
            pc = CD_INIT_SUM;
        } else if (pc == CD_INIT_SUM) {
            sum = 0;
            pc = CD_CHECK;
        } else if (pc == CD_CHECK) {
            pc = (count > 0) ? CD_BODY_ADD : CD_HALT;
        } else if (pc == CD_BODY_ADD) {
            sum = sum + count;
            pc = CD_BODY_DEC;
        } else if (pc == CD_BODY_DEC) {
            count = count - 1;
            pc = CD_CHECK;
        } else if (pc == CD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_countdown_loop(10)=%d vm_countdown_loop(15)=%d\n",
           vm_countdown_loop_target(10), vm_countdown_loop_target(15));
    return 0;
}
```
