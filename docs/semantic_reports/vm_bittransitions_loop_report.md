# vm_bittransitions_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bittransitions_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bittransitions_loop.ll`
- **Symbol:** `vm_bittransitions_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bittransitions_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bittransitions_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zeros |
| 2 | RCX=1 | 1 | 1 | 1 | yes | single bit set |
| 3 | RCX=2 | 2 | 2 | 2 | yes | bit 1 set |
| 4 | RCX=65535 | 0 | 0 | 0 | yes | all 16 bits same: 0 transitions |
| 5 | RCX=21845 | 15 | 15 | 15 | yes | 0x5555 alternating: 15 transitions |
| 6 | RCX=43690 | 15 | 15 | 15 | yes | 0xAAAA alternating |
| 7 | RCX=52428 | 7 | 7 | 7 | yes | 0xCCCC: 2-bit blocks |
| 8 | RCX=3855 | 3 | 3 | 3 | yes | 0x0F0F: 4-bit blocks |
| 9 | RCX=61680 | 3 | 3 | 3 | yes | 0xF0F0: 4-bit blocks |
| 10 | RCX=65280 | 1 | 1 | 1 | yes | 0xFF00: single transition |
| 11 | RCX=4660 | 8 | 8 | 8 | yes | 0x1234 |

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
