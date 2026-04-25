# vm_dupcount_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_dupcount_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dupcount_loop.ll`
- **Symbol:** `vm_dupcount_loop_target`
- **IR size:** 151 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | limit=1: no compares |
| 2 | RCX=1 | 0 | 0 | pass | limit=2, data=[1,0] |
| 3 | RCX=4369 | 1 | 1 | pass | 0x1111: limit=2, data=[1,1] |
| 4 | RCX=74565 | 0 | 0 | pass | 0x12345: limit=6, all distinct |
| 5 | RCX=858996001 | 0 | 0 | pass | 0x33334321: limit=2, data=[1,2] |
| 6 | RCX=2004318071 | 7 | 7 | pass | 0x77777777: limit=8, all 7s |
| 7 | RCX=287454020 | 2 | 2 | pass | 0x11223344: limit=5, data=[4,4,3,3,2] |
| 8 | RCX=305419895 | 1 | 1 | pass | 0x12345677: limit=8 |
| 9 | RCX=4294967295 | 7 | 7 | pass | all F: 7 dups |
| 10 | RCX=268439552 | 0 | 0 | pass | 0x10001000: limit=1, no scan |
| 11 | RCX=171 | 1 | 1 | pass | 0xAB: limit=4, data=[B,A,0,0] |

## Source

```c
/* PC-state VM that counts adjacent equal nibbles extracted from x.
 * Lift target: vm_dupcount_loop_target.
 * Goal: cover a loop body that loads TWO stack-array elements at adjacent
 * indices (data[i-1] and data[i]) and conditionally increments a counter
 * on equality.  Distinct from vm_runlength_loop (compares previous *bit*,
 * here previous *array element*).
 */
#include <stdio.h>

enum DcVmPc {
    DC_LOAD       = 0,
    DC_INIT_FILL  = 1,
    DC_FILL_CHECK = 2,
    DC_FILL_BODY  = 3,
    DC_FILL_INC   = 4,
    DC_INIT_SCAN  = 5,
    DC_SCAN_CHECK = 6,
    DC_SCAN_LOAD  = 7,
    DC_SCAN_TEST  = 8,
    DC_SCAN_INC_C = 9,
    DC_SCAN_INC_I = 10,
    DC_HALT       = 11,
};

__declspec(noinline)
int vm_dupcount_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int count = 0;
    int prev  = 0;
    int cur   = 0;
    int pc    = DC_LOAD;

    while (1) {
        if (pc == DC_LOAD) {
            limit = (x & 7) + 1;
            count = 0;
            pc = DC_INIT_FILL;
        } else if (pc == DC_INIT_FILL) {
            idx = 0;
            pc = DC_FILL_CHECK;
        } else if (pc == DC_FILL_CHECK) {
            pc = (idx < limit) ? DC_FILL_BODY : DC_INIT_SCAN;
        } else if (pc == DC_FILL_BODY) {
            data[idx] = (x >> (idx * 4)) & 0xF;
            pc = DC_FILL_INC;
        } else if (pc == DC_FILL_INC) {
            idx = idx + 1;
            pc = DC_FILL_CHECK;
        } else if (pc == DC_INIT_SCAN) {
            idx = 1;
            pc = DC_SCAN_CHECK;
        } else if (pc == DC_SCAN_CHECK) {
            pc = (idx < limit) ? DC_SCAN_LOAD : DC_HALT;
        } else if (pc == DC_SCAN_LOAD) {
            prev = data[idx - 1];
            cur = data[idx];
            pc = DC_SCAN_TEST;
        } else if (pc == DC_SCAN_TEST) {
            pc = (cur == prev) ? DC_SCAN_INC_C : DC_SCAN_INC_I;
        } else if (pc == DC_SCAN_INC_C) {
            count = count + 1;
            pc = DC_SCAN_INC_I;
        } else if (pc == DC_SCAN_INC_I) {
            idx = idx + 1;
            pc = DC_SCAN_CHECK;
        } else if (pc == DC_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dupcount_loop(0x77777777)=%d vm_dupcount_loop(0x11223344)=%d\n",
           vm_dupcount_loop_target(0x77777777), vm_dupcount_loop_target(0x11223344));
    return 0;
}
```
