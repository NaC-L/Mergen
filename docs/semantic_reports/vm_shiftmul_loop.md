# vm_shiftmul_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_shiftmul_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_shiftmul_loop.ll`
- **Symbol:** `vm_shiftmul_loop_target`
- **IR size:** 95 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | a=0,b=0 |
| 2 | RCX=258 | 2 | 2 | pass | a=2,b=1 |
| 3 | RCX=515 | 6 | 6 | pass | a=3,b=2 |
| 4 | RCX=3855 | 225 | 225 | pass | a=15,b=15 |
| 5 | RCX=65535 | 65025 | 65025 | pass | a=255,b=255 |
| 6 | RCX=16386 | 128 | 128 | pass | a=2,b=64 |
| 7 | RCX=32769 | 128 | 128 | pass | a=1,b=128 |
| 8 | RCX=43605 | 14450 | 14450 | pass | a=0x55,b=0xAA |
| 9 | RCX=21930 | 14450 | 14450 | pass | a=0xAA,b=0x55 |
| 10 | RCX=49344 | 36864 | 36864 | pass | a=0xC0,b=0xC0 |
| 11 | RCX=33023 | 32640 | 32640 | pass | a=0xFF,b=0x80 |

## Source

```c
/* PC-state VM running schoolbook shift-and-add multiplication.
 * Lift target: vm_shiftmul_loop_target.
 * Goal: cover an 8-trip loop whose body conditionally adds a shifted
 * multiplicand based on the LSB of a shifted multiplier - distinct from
 * vm_xor_accumulator (XOR not add) and vm_carrychain (no conditional add).
 * Inputs a = x & 0xFF and b = (x >> 8) & 0xFF; result is (a*b) & 0xFFFF.
 */
#include <stdio.h>

enum SmVmPc {
    SM_LOAD       = 0,
    SM_INIT       = 1,
    SM_CHECK      = 2,
    SM_BODY_BIT   = 3,
    SM_BODY_TEST  = 4,
    SM_BODY_SHIFT = 5,
    SM_BODY_ADD   = 6,
    SM_BODY_INC   = 7,
    SM_HALT       = 8,
};

__declspec(noinline)
int vm_shiftmul_loop_target(int x) {
    int a      = 0;
    int b      = 0;
    int i      = 0;
    int result = 0;
    int bit    = 0;
    int term   = 0;
    int pc     = SM_LOAD;

    while (1) {
        if (pc == SM_LOAD) {
            a = x & 0xFF;
            b = (x >> 8) & 0xFF;
            i = 0;
            result = 0;
            pc = SM_INIT;
        } else if (pc == SM_INIT) {
            pc = SM_CHECK;
        } else if (pc == SM_CHECK) {
            pc = (i < 8) ? SM_BODY_BIT : SM_HALT;
        } else if (pc == SM_BODY_BIT) {
            bit = (b >> i) & 1;
            pc = SM_BODY_TEST;
        } else if (pc == SM_BODY_TEST) {
            pc = (bit != 0) ? SM_BODY_SHIFT : SM_BODY_INC;
        } else if (pc == SM_BODY_SHIFT) {
            term = a << i;
            pc = SM_BODY_ADD;
        } else if (pc == SM_BODY_ADD) {
            result = result + term;
            pc = SM_BODY_INC;
        } else if (pc == SM_BODY_INC) {
            i = i + 1;
            pc = SM_CHECK;
        } else if (pc == SM_HALT) {
            return result & 0xFFFF;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_shiftmul_loop(0xFFFF)=%d vm_shiftmul_loop(0xAA55)=%d\n",
           vm_shiftmul_loop_target(0xFFFF), vm_shiftmul_loop_target(0xAA55));
    return 0;
}
```
