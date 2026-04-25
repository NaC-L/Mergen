# vm_hamming_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_hamming_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_hamming_loop.ll`
- **Symbol:** `vm_hamming_loop_target`
- **IR size:** 70 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | a=0,b=0: hamming 0 |
| 2 | RCX=18 | 2 | 2 | pass | a=2,b=1: hamming 2 |
| 3 | RCX=51 | 0 | 0 | pass | a=3,b=3: hamming 0 |
| 4 | RCX=85 | 0 | 0 | pass | a=5,b=5: hamming 0 |
| 5 | RCX=170 | 0 | 0 | pass | a=10,b=10: hamming 0 |
| 6 | RCX=240 | 4 | 4 | pass | a=0,b=15: hamming 4 |
| 7 | RCX=255 | 0 | 0 | pass | a=15,b=15: hamming 0 |
| 8 | RCX=1 | 1 | 1 | pass | a=1,b=0: hamming 1 |
| 9 | RCX=7 | 3 | 3 | pass | a=7,b=0: hamming 3 |
| 10 | RCX=128 | 1 | 1 | pass | a=0,b=8: hamming 1 |

## Source

```c
/* PC-state VM computing the Hamming distance between two 4-bit operands.
 * Lift target: vm_hamming_loop_target.
 * Goal: cover a bitwise loop with TWO symbolic operands (a = x & 0xF,
 * b = (x >> 4) & 0xF) where the body XORs and pop-counts.  The dispatcher
 * uses the dual_counter init-state pattern (explicit i=0/dist=0 in the
 * first dispatcher state) so the lifter threads initial values through the
 * loop phi correctly even on the empty-loop path (a == b).
 */
#include <stdio.h>

enum HamVmPc {
    HV_INIT      = 0,
    HV_LOAD      = 1,
    HV_CHECK     = 2,
    HV_BODY_BIT  = 3,
    HV_BODY_ADD  = 4,
    HV_BODY_SHR  = 5,
    HV_HALT      = 6,
};

__declspec(noinline)
int vm_hamming_loop_target(int x) {
    int a    = 0;
    int b    = 0;
    int v    = 0;
    int dist = 0;
    int bit  = 0;
    int pc   = HV_LOAD;

    while (1) {
        if (pc == HV_LOAD) {
            a = x & 0xF;
            b = (x >> 4) & 0xF;
            v = a ^ b;
            dist = 0;
            pc = HV_CHECK;
        } else if (pc == HV_CHECK) {
            pc = (v != 0) ? HV_BODY_BIT : HV_HALT;
        } else if (pc == HV_BODY_BIT) {
            bit = v & 1;
            pc = HV_BODY_ADD;
        } else if (pc == HV_BODY_ADD) {
            dist = dist + bit;
            pc = HV_BODY_SHR;
        } else if (pc == HV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = HV_CHECK;
        } else if (pc == HV_HALT) {
            return dist;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_hamming_loop(0x12)=%d vm_hamming_loop(0xF0)=%d\n",
           vm_hamming_loop_target(0x12), vm_hamming_loop_target(0xF0));
    return 0;
}
```
