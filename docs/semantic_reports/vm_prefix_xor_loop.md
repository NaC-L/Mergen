# vm_prefix_xor_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_prefix_xor_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_prefix_xor_loop.ll`
- **Symbol:** `vm_prefix_xor_loop_target`
- **IR size:** 148 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=1, data=[0] |
| 2 | RCX=1 | 1 | 1 | pass | limit=2, data=[1,0] |
| 3 | RCX=2 | 2 | 2 | pass | limit=3, data=[2,0,0] |
| 4 | RCX=7 | 7 | 7 | pass | limit=8, data=[7,0,..,0] |
| 5 | RCX=18 | 3 | 3 | pass | 0x12: limit=3, data=[2,1,0] |
| 6 | RCX=4660 | 4 | 4 | pass | 0x1234: limit=5 |
| 7 | RCX=74565 | 1 | 1 | pass | 0x12345: limit=6 |
| 8 | RCX=19088743 | 0 | 0 | pass | 0x1234567: limit=8 |
| 9 | RCX=305419896 | 8 | 8 | pass | 0x12345678: limit=1, only data[0]=8 |
| 10 | RCX=4294967295 | 0 | 0 | pass | all F: limit=8, alternates |
| 11 | RCX=2882400001 | 1 | 1 | pass | 0xABCDEF01: limit=2, data=[1,0] |

## Source

```c
/* PC-state VM that fills a stack array and computes an in-place cumulative
 * XOR; returns the last element.
 * Lift target: vm_prefix_xor_loop_target.
 * Goal: cover an in-place array transform driven by XOR rather than ADD;
 * distinct from vm_prefix_sum_loop (additive prefix).  Trip count is
 * symbolic from the high nibble of x so the lifter cannot fully unroll.
 */
#include <stdio.h>

enum PxVmPc {
    PX_LOAD       = 0,
    PX_INIT_FILL  = 1,
    PX_FILL_CHECK = 2,
    PX_FILL_BODY  = 3,
    PX_FILL_INC   = 4,
    PX_INIT_SCAN  = 5,
    PX_SCAN_CHECK = 6,
    PX_SCAN_BODY  = 7,
    PX_SCAN_INC   = 8,
    PX_TAIL       = 9,
    PX_HALT       = 10,
};

__declspec(noinline)
int vm_prefix_xor_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int prev  = 0;
    int cur   = 0;
    int shift = 0;
    int result = 0;
    int pc    = PX_LOAD;

    while (1) {
        if (pc == PX_LOAD) {
            limit = (x & 7) + 1;
            pc = PX_INIT_FILL;
        } else if (pc == PX_INIT_FILL) {
            idx = 0;
            pc = PX_FILL_CHECK;
        } else if (pc == PX_FILL_CHECK) {
            pc = (idx < limit) ? PX_FILL_BODY : PX_INIT_SCAN;
        } else if (pc == PX_FILL_BODY) {
            shift = idx * 4;
            data[idx] = (x >> shift) & 0xF;
            pc = PX_FILL_INC;
        } else if (pc == PX_FILL_INC) {
            idx = idx + 1;
            pc = PX_FILL_CHECK;
        } else if (pc == PX_INIT_SCAN) {
            idx = 1;
            pc = PX_SCAN_CHECK;
        } else if (pc == PX_SCAN_CHECK) {
            pc = (idx < limit) ? PX_SCAN_BODY : PX_TAIL;
        } else if (pc == PX_SCAN_BODY) {
            prev = data[idx - 1];
            cur = data[idx];
            data[idx] = prev ^ cur;
            pc = PX_SCAN_INC;
        } else if (pc == PX_SCAN_INC) {
            idx = idx + 1;
            pc = PX_SCAN_CHECK;
        } else if (pc == PX_TAIL) {
            result = data[limit - 1];
            pc = PX_HALT;
        } else if (pc == PX_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_prefix_xor_loop(0x71234567)=%d vm_prefix_xor_loop(0xFFFFFFFF)=%d\n",
           vm_prefix_xor_loop_target(0x71234567), vm_prefix_xor_loop_target((int)0xFFFFFFFFu));
    return 0;
}
```
