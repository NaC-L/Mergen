# vm_rotate_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_rotate_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_rotate_loop.ll`
- **Symbol:** `vm_rotate_loop_target`
- **IR size:** 49 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | val=0,n=0 |
| 2 | RCX=1 | 1 | 1 | pass | val=1,n=0 |
| 3 | RCX=128 | 128 | 128 | pass | val=0x80,n=0 |
| 4 | RCX=256 | 0 | 0 | pass | val=0,n=1 |
| 5 | RCX=384 | 1 | 1 | pass | val=0x80,n=1: rot left -> 1 |
| 6 | RCX=1281 | 32 | 32 | pass | val=1,n=5: rot left 5 -> 0x20 |
| 7 | RCX=1793 | 128 | 128 | pass | val=1,n=7: rot left 7 -> 0x80 |
| 8 | RCX=1877 | 170 | 170 | pass | val=0x55,n=7 |
| 9 | RCX=4095 | 255 | 255 | pass | val=0xFF,n=7: any rotation |
| 10 | RCX=1807 | 135 | 135 | pass | val=0x0F,n=7 |

## Source

```c
/* PC-state VM doing 8-bit left rotation by a symbolic count.
 * Lift target: vm_rotate_loop_target.
 * Goal: cover a bitwise loop whose body uses both shl and lshr to wrap bits
 * around (rotation, not just shift).  Both value and rotation count are
 * symbolic.  Init dispatcher state pre-writes the loop variables.
 */
#include <stdio.h>

enum RotVmPc {
    RT_LOAD       = 0,
    RT_CHECK      = 1,
    RT_BODY_HI    = 2,
    RT_BODY_LO    = 3,
    RT_BODY_OR    = 4,
    RT_BODY_MASK  = 5,
    RT_BODY_DEC   = 6,
    RT_HALT       = 7,
};

__declspec(noinline)
int vm_rotate_loop_target(int x) {
    int val   = 0;
    int n     = 0;
    int hi    = 0;
    int lo    = 0;
    int pc    = RT_LOAD;

    while (1) {
        if (pc == RT_LOAD) {
            val = x & 0xFF;
            n = (x >> 8) & 7;
            pc = RT_CHECK;
        } else if (pc == RT_CHECK) {
            pc = (n > 0) ? RT_BODY_HI : RT_HALT;
        } else if (pc == RT_BODY_HI) {
            hi = (int)((unsigned)val >> 7);
            pc = RT_BODY_LO;
        } else if (pc == RT_BODY_LO) {
            lo = val << 1;
            pc = RT_BODY_OR;
        } else if (pc == RT_BODY_OR) {
            val = lo | hi;
            pc = RT_BODY_MASK;
        } else if (pc == RT_BODY_MASK) {
            val = val & 0xFF;
            pc = RT_BODY_DEC;
        } else if (pc == RT_BODY_DEC) {
            n = n - 1;
            pc = RT_CHECK;
        } else if (pc == RT_HALT) {
            return val;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_rotate_loop(0x755)=%d vm_rotate_loop(0x70F)=%d\n",
           vm_rotate_loop_target(0x755), vm_rotate_loop_target(0x70F));
    return 0;
}
```
