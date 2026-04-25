# vm_prefix_sum_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_prefix_sum_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_prefix_sum_loop.ll`
- **Symbol:** `vm_prefix_sum_loop_target`
- **IR size:** 154 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=1, sole element 0 |
| 2 | RCX=1 | 3 | 3 | pass | limit=2: data=[1,2], prefix=[1,3] |
| 3 | RCX=2 | 9 | 9 | pass | limit=3: data=[2,3,4], prefix end=9 |
| 4 | RCX=7 | 84 | 84 | pass | limit=8: data=[7,8,..,14] sum 84 |
| 5 | RCX=15 | 36 | 36 | pass | limit=8: data=[15,0,1,..,6] wrap, sum 36 |
| 6 | RCX=16 | 0 | 0 | pass | limit=1, sole=0 (mask drops bit 4) |
| 7 | RCX=64 | 0 | 0 | pass | limit=1, sole=0 (low byte mask) |
| 8 | RCX=85 | 45 | 45 | pass | limit=6: data=[5,6,7,8,9,10] sum 45 |
| 9 | RCX=160 | 0 | 0 | pass | limit=1, sole=0 |
| 10 | RCX=255 | 36 | 36 | pass | limit=8: data=[15,0,..,6] wrap |
| 11 | RCX=4660 | 30 | 30 | pass | 0x1234: limit=5, data=[4,5,6,7,8] sum 30 |

## Source

```c
/* PC-state VM that fills a stack array and then walks it computing an
 * in-place running prefix sum.
 * Lift target: vm_prefix_sum_loop_target.
 * Goal: cover a two-phase VM where the second loop *writes back* into the
 * stack array each iteration (data[i] += data[i-1]).  Distinct from
 * vm_minarray_loop where the second pass only reads.
 */
#include <stdio.h>

enum PsVmPc {
    PS_LOAD       = 0,
    PS_INIT_FILL  = 1,
    PS_FILL_CHECK = 2,
    PS_FILL_BODY  = 3,
    PS_FILL_INC   = 4,
    PS_INIT_SCAN  = 5,
    PS_SCAN_CHECK = 6,
    PS_SCAN_LOAD  = 7,
    PS_SCAN_STORE = 8,
    PS_SCAN_INC   = 9,
    PS_TAIL       = 10,
    PS_HALT       = 11,
};

__declspec(noinline)
int vm_prefix_sum_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int prev  = 0;
    int cur   = 0;
    int sum   = 0;
    int pc    = PS_LOAD;

    while (1) {
        if (pc == PS_LOAD) {
            limit = (x & 7) + 1;
            pc = PS_INIT_FILL;
        } else if (pc == PS_INIT_FILL) {
            idx = 0;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_FILL_CHECK) {
            pc = (idx < limit) ? PS_FILL_BODY : PS_INIT_SCAN;
        } else if (pc == PS_FILL_BODY) {
            data[idx] = (x + idx) & 0xF;
            pc = PS_FILL_INC;
        } else if (pc == PS_FILL_INC) {
            idx = idx + 1;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_INIT_SCAN) {
            idx = 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_SCAN_CHECK) {
            pc = (idx < limit) ? PS_SCAN_LOAD : PS_TAIL;
        } else if (pc == PS_SCAN_LOAD) {
            prev = data[idx - 1];
            cur = data[idx];
            pc = PS_SCAN_STORE;
        } else if (pc == PS_SCAN_STORE) {
            data[idx] = prev + cur;
            pc = PS_SCAN_INC;
        } else if (pc == PS_SCAN_INC) {
            idx = idx + 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_TAIL) {
            sum = data[limit - 1];
            pc = PS_HALT;
        } else if (pc == PS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_prefix_sum_loop(0x55)=%d vm_prefix_sum_loop(0x1234)=%d\n",
           vm_prefix_sum_loop_target(0x55), vm_prefix_sum_loop_target(0x1234));
    return 0;
}
```
