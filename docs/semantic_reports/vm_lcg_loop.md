# vm_lcg_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_lcg_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_lcg_loop.ll`
- **Symbol:** `vm_lcg_loop_target`
- **IR size:** 80 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | n=0: state stays 1 |
| 2 | RCX=1 | 9 | 9 | pass | n=1, key=1: 9 |
| 3 | RCX=2 | 55 | 55 | pass | n=2, key=2 |
| 4 | RCX=5 | 157 | 157 | pass | n=5, key=5 |
| 5 | RCX=7 | 27 | 27 | pass | n=7, key=7 |
| 6 | RCX=10 | 159 | 159 | pass | n=10, key=10 |
| 7 | RCX=15 | 131 | 131 | pass | n=15, key=15 |
| 8 | RCX=16 | 1 | 1 | pass | n=0 again (mask drops bit 4 of n) |
| 9 | RCX=100 | 53 | 53 | pass | n=4, key=100 |
| 10 | RCX=255 | 83 | 83 | pass | n=15, key=0xFF |

## Source

```c
/* PC-state VM running an LCG-style mixed multiply-and-mask recurrence.
 * Lift target: vm_lcg_loop_target.
 * Goal: cover a single-state recurrence whose body mixes multiplication,
 * addition, and a bitmask in one update step:
 *   state = (state * 5 + key + 3) & 0xFF
 * Both the key and the iteration count are derived from x so neither the
 * loop bound nor the recurrence can be folded.
 */
#include <stdio.h>

enum LcgVmPc {
    LG_INIT       = 0,
    LG_LOAD_KEY   = 1,
    LG_LOAD_N     = 2,
    LG_INIT_STATE = 3,
    LG_CHECK      = 4,
    LG_BODY_MUL   = 5,
    LG_BODY_ADD   = 6,
    LG_BODY_MASK  = 7,
    LG_BODY_DEC   = 8,
    LG_HALT       = 9,
};

__declspec(noinline)
int vm_lcg_loop_target(int x) {
    int key   = 0;
    int n     = 0;
    int state = 0;
    int tmp   = 0;
    int pc    = LG_INIT;

    while (1) {
        if (pc == LG_INIT) {
            pc = LG_LOAD_KEY;
        } else if (pc == LG_LOAD_KEY) {
            key = x & 0xFF;
            pc = LG_LOAD_N;
        } else if (pc == LG_LOAD_N) {
            n = x & 0xF;
            pc = LG_INIT_STATE;
        } else if (pc == LG_INIT_STATE) {
            state = 1;
            pc = LG_CHECK;
        } else if (pc == LG_CHECK) {
            pc = (n > 0) ? LG_BODY_MUL : LG_HALT;
        } else if (pc == LG_BODY_MUL) {
            tmp = state * 5;
            pc = LG_BODY_ADD;
        } else if (pc == LG_BODY_ADD) {
            tmp = tmp + key + 3;
            pc = LG_BODY_MASK;
        } else if (pc == LG_BODY_MASK) {
            state = tmp & 0xFF;
            pc = LG_BODY_DEC;
        } else if (pc == LG_BODY_DEC) {
            n = n - 1;
            pc = LG_CHECK;
        } else if (pc == LG_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lcg_loop(7)=%d vm_lcg_loop(255)=%d\n",
           vm_lcg_loop_target(7), vm_lcg_loop_target(255));
    return 0;
}
```
