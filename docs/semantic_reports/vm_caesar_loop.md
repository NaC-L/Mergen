# vm_caesar_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 12/12 passed
- **Source:** `testcases/rewrite_smoke/vm_caesar_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_caesar_loop.ll`
- **Symbol:** `vm_caesar_loop_target`
- **IR size:** 42 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 92 | 92 | pass | shift=0 |
| 2 | RCX=1 | 100 | 100 | pass | shift=0, x=1: buf shifts up by 1 each |
| 3 | RCX=256 | 100 | 100 | pass | shift=1, x=0 |
| 4 | RCX=257 | 108 | 108 | pass | shift=1, x=1 |
| 5 | RCX=264 | 132 | 132 | pass | shift=1, x=8 |
| 6 | RCX=272 | 100 | 100 | pass | shift=1, x=16 |
| 7 | RCX=768 | 116 | 116 | pass | shift=3, x=0 |
| 8 | RCX=2581 | 116 | 116 | pass | 0xA15: shift=10, x=0x15 |
| 9 | RCX=3074 | 108 | 108 | pass | 0xC02: shift=12, x=2 |
| 10 | RCX=7936 | 116 | 116 | pass | 0x1F00: shift=31, x=0 |
| 11 | RCX=255 | 116 | 116 | pass | 0xFF: shift=0, x=0xFF |
| 12 | RCX=4660 | 140 | 140 | pass | 0x1234 |

## Source

```c
/* PC-state VM running an additive (Caesar-style) shift transform on a stack
 * buffer.
 * Lift target: vm_caesar_loop_target.
 * Goal: cover a two-phase VM (fill, transform-in-place, sum) where the
 * transformation is ADD+MASK rather than XOR.  Distinct from
 * vm_xordecrypt_loop (XOR+sum).
 */
#include <stdio.h>

enum CsVmPc {
    CS_LOAD       = 0,
    CS_INIT_FILL  = 1,
    CS_FILL_CHECK = 2,
    CS_FILL_BODY  = 3,
    CS_FILL_INC   = 4,
    CS_INIT_TX    = 5,
    CS_TX_CHECK   = 6,
    CS_TX_BODY    = 7,
    CS_TX_INC     = 8,
    CS_INIT_SUM   = 9,
    CS_SUM_CHECK  = 10,
    CS_SUM_BODY   = 11,
    CS_SUM_INC    = 12,
    CS_HALT       = 13,
};

__declspec(noinline)
int vm_caesar_loop_target(int x) {
    int buf[8];
    int idx     = 0;
    int shift   = 0;
    int byte    = 0;
    int sum     = 0;
    int pc      = CS_LOAD;

    while (1) {
        if (pc == CS_LOAD) {
            shift = (x >> 8) & 0x1F;
            sum = 0;
            pc = CS_INIT_FILL;
        } else if (pc == CS_INIT_FILL) {
            idx = 0;
            pc = CS_FILL_CHECK;
        } else if (pc == CS_FILL_CHECK) {
            pc = (idx < 8) ? CS_FILL_BODY : CS_INIT_TX;
        } else if (pc == CS_FILL_BODY) {
            buf[idx] = (x + idx * 0x11) & 0x1F;
            pc = CS_FILL_INC;
        } else if (pc == CS_FILL_INC) {
            idx = idx + 1;
            pc = CS_FILL_CHECK;
        } else if (pc == CS_INIT_TX) {
            idx = 0;
            pc = CS_TX_CHECK;
        } else if (pc == CS_TX_CHECK) {
            pc = (idx < 8) ? CS_TX_BODY : CS_INIT_SUM;
        } else if (pc == CS_TX_BODY) {
            byte = buf[idx];
            buf[idx] = (byte + shift) & 0x1F;
            pc = CS_TX_INC;
        } else if (pc == CS_TX_INC) {
            idx = idx + 1;
            pc = CS_TX_CHECK;
        } else if (pc == CS_INIT_SUM) {
            idx = 0;
            pc = CS_SUM_CHECK;
        } else if (pc == CS_SUM_CHECK) {
            pc = (idx < 8) ? CS_SUM_BODY : CS_HALT;
        } else if (pc == CS_SUM_BODY) {
            sum = sum + buf[idx];
            pc = CS_SUM_INC;
        } else if (pc == CS_SUM_INC) {
            idx = idx + 1;
            pc = CS_SUM_CHECK;
        } else if (pc == CS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_caesar_loop(0x108)=%d vm_caesar_loop(0x1234)=%d\n",
           vm_caesar_loop_target(0x108), vm_caesar_loop_target(0x1234));
    return 0;
}
```
