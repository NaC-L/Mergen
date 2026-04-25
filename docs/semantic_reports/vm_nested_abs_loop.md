# vm_nested_abs_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_nested_abs_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_nested_abs_loop.ll`
- **Symbol:** `vm_nested_abs_loop_target`
- **IR size:** 106 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | a=1, b=1, v=0 |
| 2 | RCX=16 | 1 | 1 | pass | 0x10: a=1,b=1,v=1 |
| 3 | RCX=64 | 4 | 4 | pass | 0x40: a=1,b=1,v=4 |
| 4 | RCX=119 | 56 | 56 | pass | 0x77: a=4,b=2,v=7 |
| 5 | RCX=192 | 12 | 12 | pass | 0xC0: a=1,b=1,v=12 |
| 6 | RCX=255 | 206 | 206 | pass | 0xFF: a=4,b=4,v=15 |
| 7 | RCX=256 | 16 | 16 | pass | 0x100: a=1,b=1,v=16 |
| 8 | RCX=2748 | 714 | 714 | pass | 0xABC: a=1,b=4,v=171 |
| 9 | RCX=291 | 36 | 36 | pass | 0x123: a=4,b=1,v=18 |
| 10 | RCX=65535 | 4032 | 4032 | pass | 0xFFFF: a=4,b=4,v=255 |
| 11 | RCX=2004318071 | 888 | 888 | pass | 0x77777777: a=4,b=2,v=119 |

## Source

```c
/* PC-state VM with nested counted loops whose inner body calls abs().
 * Lift target: vm_nested_abs_loop_target.
 * Goal: cover a TWO-deep PC-state nested loop where the inner body issues
 * an imported intrinsic call.  Distinct from vm_nested_loop (no calls) and
 * vm_imported_abs_loop (single non-nested loop).  Computes
 *   sum_{i<a} sum_{j<b} abs((i*7) - (j*5) - v)
 * with a, b, v all derived from symbolic x.
 */
#include <stdio.h>
#include <stdlib.h>

enum NaVmPc {
    NA_LOAD       = 0,
    NA_OUTER_INIT = 1,
    NA_OUTER_CHECK = 2,
    NA_INNER_INIT = 3,
    NA_INNER_CHECK = 4,
    NA_BODY_DELTA = 5,
    NA_BODY_CALL  = 6,
    NA_BODY_ADD   = 7,
    NA_INNER_INC  = 8,
    NA_OUTER_INC  = 9,
    NA_HALT       = 10,
};

__declspec(noinline)
int vm_nested_abs_loop_target(int x) {
    int a     = 0;
    int b     = 0;
    int v     = 0;
    int i     = 0;
    int j     = 0;
    int acc   = 0;
    int delta = 0;
    int abs_r = 0;
    int pc    = NA_LOAD;

    while (1) {
        if (pc == NA_LOAD) {
            a = (x & 3) + 1;
            b = ((x >> 2) & 3) + 1;
            v = (x >> 4) & 0xFF;
            acc = 0;
            pc = NA_OUTER_INIT;
        } else if (pc == NA_OUTER_INIT) {
            i = 0;
            pc = NA_OUTER_CHECK;
        } else if (pc == NA_OUTER_CHECK) {
            pc = (i < a) ? NA_INNER_INIT : NA_HALT;
        } else if (pc == NA_INNER_INIT) {
            j = 0;
            pc = NA_INNER_CHECK;
        } else if (pc == NA_INNER_CHECK) {
            pc = (j < b) ? NA_BODY_DELTA : NA_OUTER_INC;
        } else if (pc == NA_BODY_DELTA) {
            delta = (i * 7) - (j * 5) - v;
            pc = NA_BODY_CALL;
        } else if (pc == NA_BODY_CALL) {
            abs_r = abs(delta);
            pc = NA_BODY_ADD;
        } else if (pc == NA_BODY_ADD) {
            acc = acc + abs_r;
            pc = NA_INNER_INC;
        } else if (pc == NA_INNER_INC) {
            j = j + 1;
            pc = NA_INNER_CHECK;
        } else if (pc == NA_OUTER_INC) {
            i = i + 1;
            pc = NA_OUTER_CHECK;
        } else if (pc == NA_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_nested_abs_loop(0xABC)=%d vm_nested_abs_loop(0xFFFF)=%d\n",
           vm_nested_abs_loop_target(0xABC), vm_nested_abs_loop_target(0xFFFF));
    return 0;
}
```
