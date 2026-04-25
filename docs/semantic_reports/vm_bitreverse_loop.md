# vm_bitreverse_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_bitreverse_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bitreverse_loop.ll`
- **Symbol:** `vm_bitreverse_loop_target`
- **IR size:** 27 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | reverse(0x00) |
| 2 | RCX=1 | 128 | 128 | pass | reverse(0x01) = 0x80 |
| 3 | RCX=128 | 1 | 1 | pass | reverse(0x80) = 0x01 |
| 4 | RCX=170 | 85 | 85 | pass | reverse(0xAA) = 0x55 |
| 5 | RCX=85 | 170 | 170 | pass | reverse(0x55) = 0xAA |
| 6 | RCX=255 | 255 | 255 | pass | reverse(0xFF) = 0xFF |
| 7 | RCX=18 | 72 | 72 | pass | reverse(0x12) = 0x48 |
| 8 | RCX=51 | 204 | 204 | pass | reverse(0x33) = 0xCC |
| 9 | RCX=64 | 2 | 2 | pass | reverse(0x40) = 0x02 |
| 10 | RCX=256 | 0 | 0 | pass | mask drops bit 8 |

## Source

```c
/* PC-state VM that reverses the low 8 bits of x via shift+OR accumulation.
 * Lift target: vm_bitreverse_loop_target.
 * Goal: cover a fixed-trip-count loop whose body uses both shifts and a
 * bitwise OR to accumulate a result, exercising loop body shapes the
 * additive/multiplicative samples don't reach.
 */
#include <stdio.h>

enum BrVmPc {
    BRV_INIT       = 0,
    BRV_LOAD_VAL   = 1,
    BRV_INIT_RES   = 2,
    BRV_INIT_IDX   = 3,
    BRV_CHECK      = 4,
    BRV_BODY_SHL   = 5,
    BRV_BODY_BIT   = 6,
    BRV_BODY_OR    = 7,
    BRV_BODY_SHR   = 8,
    BRV_BODY_INC   = 9,
    BRV_HALT       = 10,
};

__declspec(noinline)
int vm_bitreverse_loop_target(int x) {
    int v   = 0;
    int res = 0;
    int idx = 0;
    int bit = 0;
    int pc  = BRV_INIT;

    while (1) {
        if (pc == BRV_INIT) {
            pc = BRV_LOAD_VAL;
        } else if (pc == BRV_LOAD_VAL) {
            v = x & 0xFF;
            pc = BRV_INIT_RES;
        } else if (pc == BRV_INIT_RES) {
            res = 0;
            pc = BRV_INIT_IDX;
        } else if (pc == BRV_INIT_IDX) {
            idx = 0;
            pc = BRV_CHECK;
        } else if (pc == BRV_CHECK) {
            pc = (idx < 8) ? BRV_BODY_SHL : BRV_HALT;
        } else if (pc == BRV_BODY_SHL) {
            res = res << 1;
            pc = BRV_BODY_BIT;
        } else if (pc == BRV_BODY_BIT) {
            bit = v & 1;
            pc = BRV_BODY_OR;
        } else if (pc == BRV_BODY_OR) {
            res = res | bit;
            pc = BRV_BODY_SHR;
        } else if (pc == BRV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = BRV_BODY_INC;
        } else if (pc == BRV_BODY_INC) {
            idx = idx + 1;
            pc = BRV_CHECK;
        } else if (pc == BRV_HALT) {
            return res;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_bitreverse_loop(0xAA)=%d vm_bitreverse_loop(0x12)=%d\n",
           vm_bitreverse_loop_target(0xAA), vm_bitreverse_loop_target(0x12));
    return 0;
}
```
