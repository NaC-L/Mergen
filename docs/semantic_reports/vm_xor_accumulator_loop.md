# vm_xor_accumulator_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_xor_accumulator_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xor_accumulator_loop.ll`
- **Symbol:** `vm_xor_accumulator_loop_target`
- **IR size:** 32 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | key=0: zero accumulator |
| 2 | RCX=1 | 0 | 0 | pass | key=1: 1^2^3^4^5^6^7=0 |
| 3 | RCX=2 | 0 | 0 | pass | key=2: doubled bitstring still cancels |
| 4 | RCX=3 | 8 | 8 | pass | key=3: nontrivial |
| 5 | RCX=5 | 48 | 48 | pass | key=5 |
| 6 | RCX=7 | 56 | 56 | pass | key=7 |
| 7 | RCX=15 | 120 | 120 | pass | key=15 |
| 8 | RCX=255 | 2040 | 2040 | pass | key=0xFF: large products |

## Source

```c
/* PC-state VM accumulating XOR of i*k for i in 0..7, where k = x & 0xFF.
 * Lift target: vm_xor_accumulator_loop_target.
 * Goal: cover a fixed-trip-count loop whose body uses multiplication and
 * XOR (not add) into the accumulator.  The constant key is replaced by a
 * symbolic key derived from x, so the lifter cannot collapse the XOR
 * accumulator to a constant.
 */
#include <stdio.h>

enum XorVmPc {
    XV_INIT      = 0,
    XV_LOAD_KEY  = 1,
    XV_INIT_ACC  = 2,
    XV_INIT_IDX  = 3,
    XV_CHECK     = 4,
    XV_BODY_MUL  = 5,
    XV_BODY_XOR  = 6,
    XV_BODY_INC  = 7,
    XV_HALT      = 8,
};

__declspec(noinline)
int vm_xor_accumulator_loop_target(int x) {
    int key  = 0;
    int acc  = 0;
    int idx  = 0;
    int prod = 0;
    int pc   = XV_INIT;

    while (1) {
        if (pc == XV_INIT) {
            pc = XV_LOAD_KEY;
        } else if (pc == XV_LOAD_KEY) {
            key = x & 0xFF;
            pc = XV_INIT_ACC;
        } else if (pc == XV_INIT_ACC) {
            acc = 0;
            pc = XV_INIT_IDX;
        } else if (pc == XV_INIT_IDX) {
            idx = 0;
            pc = XV_CHECK;
        } else if (pc == XV_CHECK) {
            pc = (idx < 8) ? XV_BODY_MUL : XV_HALT;
        } else if (pc == XV_BODY_MUL) {
            prod = idx * key;
            pc = XV_BODY_XOR;
        } else if (pc == XV_BODY_XOR) {
            acc = acc ^ prod;
            pc = XV_BODY_INC;
        } else if (pc == XV_BODY_INC) {
            idx = idx + 1;
            pc = XV_CHECK;
        } else if (pc == XV_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_xor_accumulator_loop(15)=%d vm_xor_accumulator_loop(255)=%d\n",
           vm_xor_accumulator_loop_target(15), vm_xor_accumulator_loop_target(255));
    return 0;
}
```
