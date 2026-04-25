# vm_piecewise_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_piecewise_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_piecewise_loop.ll`
- **Symbol:** `vm_piecewise_loop_target`
- **IR size:** 87 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | v=0, n=0 |
| 2 | RCX=256 | 0 | 0 | pass | v=0, n=1: 0*2=0 |
| 3 | RCX=257 | 2 | 2 | pass | v=1, n=1: 1*2=2 |
| 4 | RCX=306 | 80 | 80 | pass | v=50, n=1: 50+30=80 |
| 5 | RCX=456 | 100 | 100 | pass | v=200, n=1: 200-100=100 |
| 6 | RCX=768 | 0 | 0 | pass | v=0, n=3 |
| 7 | RCX=1315 | 190 | 190 | pass | 0x523: v=35, n=5 |
| 8 | RCX=1801 | 192 | 192 | pass | 0x709: v=9, n=7 |
| 9 | RCX=3967 | 187 | 187 | pass | 0xF7F: v=127, n=15 |
| 10 | RCX=4095 | 185 | 185 | pass | 0xFFF: v=255, n=15 |
| 11 | RCX=16 | 16 | 16 | pass | v=16, n=0: unchanged |

## Source

```c
/* PC-state VM applying a piecewise linear function repeatedly to a single
 * accumulator.
 * Lift target: vm_piecewise_loop_target.
 * Goal: cover a loop body that selects one of three transformations based
 * on which range the current value falls in, with a single sequential
 * dependency on the previous iteration's result.  Distinct from
 * vm_classify_loop (which counts class membership) and vm_collatz_loop
 * (data-dependent path with two branches).
 */
#include <stdio.h>

enum PwVmPc {
    PW_LOAD       = 0,
    PW_INIT       = 1,
    PW_CHECK      = 2,
    PW_BODY_TEST_LO = 3,
    PW_BODY_TEST_HI = 4,
    PW_BODY_DOUBLE = 5,
    PW_BODY_OFFSET = 6,
    PW_BODY_SHRINK = 7,
    PW_BODY_DEC   = 8,
    PW_HALT       = 9,
};

__declspec(noinline)
int vm_piecewise_loop_target(int x) {
    int v   = 0;
    int n   = 0;
    int pc  = PW_LOAD;

    while (1) {
        if (pc == PW_LOAD) {
            v = x & 0xFF;
            n = (x >> 8) & 0xF;
            pc = PW_INIT;
        } else if (pc == PW_INIT) {
            pc = PW_CHECK;
        } else if (pc == PW_CHECK) {
            pc = (n > 0) ? PW_BODY_TEST_LO : PW_HALT;
        } else if (pc == PW_BODY_TEST_LO) {
            pc = (v < 50) ? PW_BODY_DOUBLE : PW_BODY_TEST_HI;
        } else if (pc == PW_BODY_TEST_HI) {
            pc = (v < 200) ? PW_BODY_OFFSET : PW_BODY_SHRINK;
        } else if (pc == PW_BODY_DOUBLE) {
            v = (v * 2) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_OFFSET) {
            v = (v + 30) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_SHRINK) {
            v = (v - 100) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_DEC) {
            n = n - 1;
            pc = PW_CHECK;
        } else if (pc == PW_HALT) {
            return v;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_piecewise_loop(0x709)=%d vm_piecewise_loop(0xFFF)=%d\n",
           vm_piecewise_loop_target(0x709), vm_piecewise_loop_target(0xFFF));
    return 0;
}
```
