# vm_gcd_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/vm_gcd_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_gcd_loop.ll`
- **Symbol:** `vm_gcd_loop_target`
- **IR size:** 46 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | a=1, b=1: gcd 1 |
| 2 | RCX=18 | 1 | 1 | pass | a=3, b=2: gcd 1 |
| 3 | RCX=102 | 7 | 7 | pass | a=7, b=7: gcd 7 |
| 4 | RCX=136 | 9 | 9 | pass | a=9, b=9: gcd 9 |
| 5 | RCX=53 | 2 | 2 | pass | a=6, b=4: gcd 2 |
| 6 | RCX=87 | 2 | 2 | pass | a=8, b=6: gcd 2 |
| 7 | RCX=207 | 1 | 1 | pass | a=16, b=13: gcd 1 |
| 8 | RCX=255 | 16 | 16 | pass | a=16, b=16: gcd 16 |

## Source

```c
/* PC-state VM running the Euclidean GCD algorithm.
 * Lift target: vm_gcd_loop_target.
 * Goal: cover a non-counted loop driven by a modulo recurrence inside the VM
 * body.  Inputs a = (x & 0xF) + 1 and b = ((x >> 4) & 0xF) + 1 keep both
 * operands in [1, 16] and symbolic, so the lifter cannot fold the loop.
 */
#include <stdio.h>

enum GcdVmPc {
    GV_INIT     = 0,
    GV_LOAD_A   = 1,
    GV_LOAD_B   = 2,
    GV_CHECK    = 3,
    GV_BODY_MOD = 4,
    GV_BODY_SWAP= 5,
    GV_HALT     = 6,
};

__declspec(noinline)
int vm_gcd_loop_target(int x) {
    int a    = 0;
    int b    = 0;
    int tmp  = 0;
    int pc   = GV_INIT;

    while (1) {
        if (pc == GV_INIT) {
            pc = GV_LOAD_A;
        } else if (pc == GV_LOAD_A) {
            a = (x & 0xF) + 1;
            pc = GV_LOAD_B;
        } else if (pc == GV_LOAD_B) {
            b = ((x >> 4) & 0xF) + 1;
            pc = GV_CHECK;
        } else if (pc == GV_CHECK) {
            pc = (b != 0) ? GV_BODY_MOD : GV_HALT;
        } else if (pc == GV_BODY_MOD) {
            tmp = a % b;
            pc = GV_BODY_SWAP;
        } else if (pc == GV_BODY_SWAP) {
            a = b;
            b = tmp;
            pc = GV_CHECK;
        } else if (pc == GV_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_gcd_loop(0x66)=%d vm_gcd_loop(0x57)=%d\n",
           vm_gcd_loop_target(0x66), vm_gcd_loop_target(0x57));
    return 0;
}
```
