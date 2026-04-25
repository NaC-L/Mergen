# vm_abs_array_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_abs_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_abs_array_loop.ll`
- **Symbol:** `vm_abs_array_loop_target`
- **IR size:** 151 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=1, threshold=0 |
| 2 | RCX=1 | 1000 | 1000 | pass | limit=2, threshold=0: \|0\|+\|1000\| |
| 3 | RCX=7 | 28000 | 28000 | pass | limit=8, threshold=0 |
| 4 | RCX=16 | 2 | 2 | pass | 0x10: limit=1, threshold=2 |
| 5 | RCX=128 | 16 | 16 | pass | 0x80: limit=1, threshold=16 |
| 6 | RCX=255 | 27814 | 27814 | pass | 0xFF: limit=8, threshold=31 |
| 7 | RCX=256 | 32 | 32 | pass | 0x100: limit=1, threshold=32 |
| 8 | RCX=4096 | 512 | 512 | pass | 0x1000: limit=1, threshold=512 |
| 9 | RCX=43981 | 17982 | 17982 | pass | 0xABCD: limit=6 |
| 10 | RCX=65535 | 37528 | 37528 | pass | 0xFFFF: limit=8 |
| 11 | RCX=32767 | 16190 | 16190 | pass | 0x7FFF: limit=8 |

## Source

```c
/* PC-state VM that fills a stack array with abs() values, then sums them.
 * Lift target: vm_abs_array_loop_target.
 * Goal: cover a two-phase VM where (1) the fill loop body issues an
 * imported call (abs) and stores the result into a stack-array slot, and
 * (2) the sum loop accumulates from the same stack array.  Distinct from
 * vm_imported_abs_loop (single accumulator only) and vm_prefix_sum_loop
 * (no imported call).  Tests how the lifter pairs a CRT intrinsic call
 * with a same-iteration indexed stack store.
 */
#include <stdio.h>
#include <stdlib.h>

enum AaVmPc {
    AA_LOAD       = 0,
    AA_INIT_FILL  = 1,
    AA_FILL_CHECK = 2,
    AA_FILL_DELTA = 3,
    AA_FILL_CALL  = 4,
    AA_FILL_STORE = 5,
    AA_FILL_INC   = 6,
    AA_INIT_SUM   = 7,
    AA_SUM_CHECK  = 8,
    AA_SUM_BODY   = 9,
    AA_SUM_INC    = 10,
    AA_HALT       = 11,
};

__declspec(noinline)
int vm_abs_array_loop_target(int x) {
    int buf[8];
    int limit     = 0;
    int idx       = 0;
    int threshold = 0;
    int delta     = 0;
    int abs_r     = 0;
    int sum       = 0;
    int pc        = AA_LOAD;

    while (1) {
        if (pc == AA_LOAD) {
            limit = (x & 7) + 1;
            threshold = (x >> 3) & 0xFFFF;
            sum = 0;
            pc = AA_INIT_FILL;
        } else if (pc == AA_INIT_FILL) {
            idx = 0;
            pc = AA_FILL_CHECK;
        } else if (pc == AA_FILL_CHECK) {
            pc = (idx < limit) ? AA_FILL_DELTA : AA_INIT_SUM;
        } else if (pc == AA_FILL_DELTA) {
            delta = (idx * 1000) - threshold;
            pc = AA_FILL_CALL;
        } else if (pc == AA_FILL_CALL) {
            abs_r = abs(delta);
            pc = AA_FILL_STORE;
        } else if (pc == AA_FILL_STORE) {
            buf[idx] = abs_r;
            pc = AA_FILL_INC;
        } else if (pc == AA_FILL_INC) {
            idx = idx + 1;
            pc = AA_FILL_CHECK;
        } else if (pc == AA_INIT_SUM) {
            idx = 0;
            pc = AA_SUM_CHECK;
        } else if (pc == AA_SUM_CHECK) {
            pc = (idx < limit) ? AA_SUM_BODY : AA_HALT;
        } else if (pc == AA_SUM_BODY) {
            sum = sum + buf[idx];
            pc = AA_SUM_INC;
        } else if (pc == AA_SUM_INC) {
            idx = idx + 1;
            pc = AA_SUM_CHECK;
        } else if (pc == AA_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_abs_array_loop(0xABCD)=%d vm_abs_array_loop(0xFFFF)=%d\n",
           vm_abs_array_loop_target(0xABCD), vm_abs_array_loop_target(0xFFFF));
    return 0;
}
```
