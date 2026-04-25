# vm_bittransitions_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_bittransitions_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bittransitions_loop.ll`
- **Symbol:** `vm_bittransitions_loop_target`
- **IR size:** 77 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | all zeros |
| 2 | RCX=1 | 1 | 1 | pass | single bit set |
| 3 | RCX=2 | 2 | 2 | pass | bit 1 set |
| 4 | RCX=65535 | 0 | 0 | pass | all 16 bits same: 0 transitions |
| 5 | RCX=21845 | 15 | 15 | pass | 0x5555 alternating: 15 transitions |
| 6 | RCX=43690 | 15 | 15 | pass | 0xAAAA alternating |
| 7 | RCX=52428 | 7 | 7 | pass | 0xCCCC: 2-bit blocks |
| 8 | RCX=3855 | 3 | 3 | pass | 0x0F0F: 4-bit blocks |
| 9 | RCX=61680 | 3 | 3 | pass | 0xF0F0: 4-bit blocks |
| 10 | RCX=65280 | 1 | 1 | pass | 0xFF00: single transition |
| 11 | RCX=4660 | 8 | 8 | pass | 0x1234 |

## Source

```c
/* PC-state VM that counts adjacent-bit transitions in the low 16 bits of x.
 * Lift target: vm_bittransitions_loop_target.
 * Goal: cover a loop body that examines TWO bits per iteration via XOR-and-mask.
 * Branchless body (count += diff) keeps the count slot always written so the
 * lifter doesn't promote it to phi-undef on iterations where no transition
 * occurs.
 */
#include <stdio.h>

enum BtVmPc {
    BT_LOAD       = 0,
    BT_INIT       = 1,
    BT_CHECK      = 2,
    BT_BODY_DIFF  = 3,
    BT_BODY_ADD   = 4,
    BT_BODY_INC   = 5,
    BT_HALT       = 6,
};

__declspec(noinline)
int vm_bittransitions_loop_target(int x) {
    int idx   = 0;
    int count = 0;
    int diff  = 0;
    int pc    = BT_LOAD;

    while (1) {
        if (pc == BT_LOAD) {
            idx = 0;
            count = 0;
            pc = BT_INIT;
        } else if (pc == BT_INIT) {
            pc = BT_CHECK;
        } else if (pc == BT_CHECK) {
            pc = (idx < 15) ? BT_BODY_DIFF : BT_HALT;
        } else if (pc == BT_BODY_DIFF) {
            diff = ((x >> idx) ^ (x >> (idx + 1))) & 1;
            pc = BT_BODY_ADD;
        } else if (pc == BT_BODY_ADD) {
            count = count + diff;
            pc = BT_BODY_INC;
        } else if (pc == BT_BODY_INC) {
            idx = idx + 1;
            pc = BT_CHECK;
        } else if (pc == BT_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_bittransitions_loop(0x5555)=%d vm_bittransitions_loop(0x1234)=%d\n",
           vm_bittransitions_loop_target(0x5555), vm_bittransitions_loop_target(0x1234));
    return 0;
}
```
