# vm_zigzag_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_zigzag_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_zigzag_loop.ll`
- **Symbol:** `vm_zigzag_loop_target`
- **IR size:** 80 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=0 |
| 2 | RCX=1 | 0 | 0 | pass | limit=1: 0 |
| 3 | RCX=2 | 4294967295 | 4294967295 | pass | limit=2: -1 unsigned |
| 4 | RCX=4 | 4294967294 | 4294967294 | pass | limit=4: -2 unsigned |
| 5 | RCX=5 | 2 | 2 | pass | limit=5: 2 |
| 6 | RCX=10 | 4294967291 | 4294967291 | pass | limit=10: -5 unsigned |
| 7 | RCX=11 | 5 | 5 | pass | limit=11: 5 |
| 8 | RCX=50 | 4294967271 | 4294967271 | pass | limit=50: -25 unsigned |
| 9 | RCX=100 | 4294967246 | 4294967246 | pass | limit=100: -50 unsigned |
| 10 | RCX=200 | 4294967196 | 4294967196 | pass | limit=200: -100 unsigned |
| 11 | RCX=255 | 127 | 127 | pass | limit=255: 127 |

## Source

```c
/* PC-state VM with alternating-sign accumulator: parity branch picks
 * add-vs-subtract on a single counter.
 * Lift target: vm_zigzag_loop_target.
 * Goal: cover a loop body where the parity of i selects which arithmetic
 * operation runs on the same accumulator slot.  Distinct from
 * vm_dual_counter_loop (two separate counters via parity) and
 * vm_classify_loop (three-way branch with single packed accumulator).
 */
#include <stdio.h>

enum ZzVmPc {
    ZZ_LOAD       = 0,
    ZZ_INIT       = 1,
    ZZ_CHECK      = 2,
    ZZ_TEST_PAR   = 3,
    ZZ_BODY_SUB   = 4,
    ZZ_BODY_ADD   = 5,
    ZZ_BODY_INC   = 6,
    ZZ_HALT       = 7,
};

__declspec(noinline)
int vm_zigzag_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int acc   = 0;
    int pc    = ZZ_LOAD;

    while (1) {
        if (pc == ZZ_LOAD) {
            limit = x & 0xFF;
            idx = 0;
            acc = 0;
            pc = ZZ_INIT;
        } else if (pc == ZZ_INIT) {
            pc = ZZ_CHECK;
        } else if (pc == ZZ_CHECK) {
            pc = (idx < limit) ? ZZ_TEST_PAR : ZZ_HALT;
        } else if (pc == ZZ_TEST_PAR) {
            pc = ((idx & 1) != 0) ? ZZ_BODY_SUB : ZZ_BODY_ADD;
        } else if (pc == ZZ_BODY_SUB) {
            acc = acc - idx;
            pc = ZZ_BODY_INC;
        } else if (pc == ZZ_BODY_ADD) {
            acc = acc + idx;
            pc = ZZ_BODY_INC;
        } else if (pc == ZZ_BODY_INC) {
            idx = idx + 1;
            pc = ZZ_CHECK;
        } else if (pc == ZZ_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_zigzag_loop(11)=%d vm_zigzag_loop(255)=%d\n",
           vm_zigzag_loop_target(11), vm_zigzag_loop_target(255));
    return 0;
}
```
