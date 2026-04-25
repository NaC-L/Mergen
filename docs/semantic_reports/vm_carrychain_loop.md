# vm_carrychain_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_carrychain_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_carrychain_loop.ll`
- **Symbol:** `vm_carrychain_loop_target`
- **IR size:** 110 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | a=0,b=0 |
| 2 | RCX=1 | 1 | 1 | pass | a=1,b=0 |
| 3 | RCX=256 | 1 | 1 | pass | a=0,b=1 |
| 4 | RCX=257 | 2 | 2 | pass | a=1,b=1: 1+1=2 |
| 5 | RCX=258 | 3 | 3 | pass | a=2,b=1 |
| 6 | RCX=65535 | 510 | 510 | pass | a=0xFF,b=0xFF: 510 with carry |
| 7 | RCX=3855 | 30 | 30 | pass | a=0x0F,b=0x0F |
| 8 | RCX=61680 | 480 | 480 | pass | a=0xF0,b=0xF0: carry-out |
| 9 | RCX=43605 | 255 | 255 | pass | a=0x55,b=0xAA: 0xFF |
| 10 | RCX=33023 | 383 | 383 | pass | a=0xFF,b=0x80: carry |
| 11 | RCX=128 | 128 | 128 | pass | a=0x80,b=0 |

## Source

```c
/* PC-state VM running an 8-bit ripple-carry adder bit-by-bit.
 * Lift target: vm_carrychain_loop_target.
 * Goal: cover a fixed-trip-count loop where each iteration depends on the
 * carry produced in the previous iteration (sequential dependency that
 * cannot be parallelised by the optimizer).  Inputs a = x & 0xFF and
 * b = (x >> 8) & 0xFF, output is (a+b) packed as low byte | (carry<<8).
 */
#include <stdio.h>

enum CcVmPc {
    CC_LOAD     = 0,
    CC_INIT     = 1,
    CC_CHECK    = 2,
    CC_BODY_BA  = 3,
    CC_BODY_BB  = 4,
    CC_BODY_SUM = 5,
    CC_BODY_NC  = 6,
    CC_BODY_OR  = 7,
    CC_BODY_INC = 8,
    CC_PACK     = 9,
    CC_HALT     = 10,
};

__declspec(noinline)
int vm_carrychain_loop_target(int x) {
    int a       = 0;
    int b       = 0;
    int i       = 0;
    int carry   = 0;
    int result  = 0;
    int ba      = 0;
    int bb      = 0;
    int bs      = 0;
    int nc      = 0;
    int xor_ab  = 0;
    int pc      = CC_LOAD;

    while (1) {
        if (pc == CC_LOAD) {
            a = x & 0xFF;
            b = (x >> 8) & 0xFF;
            i = 0;
            carry = 0;
            result = 0;
            pc = CC_INIT;
        } else if (pc == CC_INIT) {
            pc = CC_CHECK;
        } else if (pc == CC_CHECK) {
            pc = (i < 8) ? CC_BODY_BA : CC_PACK;
        } else if (pc == CC_BODY_BA) {
            ba = (a >> i) & 1;
            pc = CC_BODY_BB;
        } else if (pc == CC_BODY_BB) {
            bb = (b >> i) & 1;
            pc = CC_BODY_SUM;
        } else if (pc == CC_BODY_SUM) {
            xor_ab = ba ^ bb;
            bs = xor_ab ^ carry;
            pc = CC_BODY_NC;
        } else if (pc == CC_BODY_NC) {
            nc = (ba & bb) | (carry & xor_ab);
            pc = CC_BODY_OR;
        } else if (pc == CC_BODY_OR) {
            result = result | (bs << i);
            carry = nc;
            pc = CC_BODY_INC;
        } else if (pc == CC_BODY_INC) {
            i = i + 1;
            pc = CC_CHECK;
        } else if (pc == CC_PACK) {
            result = result | (carry << 8);
            pc = CC_HALT;
        } else if (pc == CC_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_carrychain_loop(0xFFFF)=%d vm_carrychain_loop(0xAA55)=%d\n",
           vm_carrychain_loop_target(0xFFFF), vm_carrychain_loop_target(0xAA55));
    return 0;
}
```
