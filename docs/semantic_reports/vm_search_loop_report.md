# vm_search_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_search_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_search_loop.ll`
- **Symbol:** `vm_search_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_search_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_search_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 8 | 8 | 8 | yes | target=1: not in table |
| 2 | RCX=2 | 0 | 0 | 0 | yes | target=3: index 0 |
| 3 | RCX=6 | 1 | 1 | 1 | yes | target=7: index 1 |
| 4 | RCX=10 | 2 | 2 | 2 | yes | target=11: index 2 |
| 5 | RCX=12 | 3 | 3 | 3 | yes | target=13: index 3 |
| 6 | RCX=22 | 1 | 1 | 1 | yes | target=7 again after mask: index 1 |
| 7 | RCX=28 | 3 | 3 | 3 | yes | target=13 again after mask: index 3 |
| 8 | RCX=4 | 8 | 8 | 8 | yes | target=5: not in table |
| 9 | RCX=15 | 8 | 8 | 8 | yes | target=16: not in table |
| 10 | RCX=16 | 8 | 8 | 8 | yes | target=1 again (mask drops bit 4) |

## Source

```c
/* PC-state VM doing a linear search through a stack-resident table.
 * Lift target: vm_search_loop_target.
 * Goal: cover a loop whose body reads from a stack array and exits early
 * via a state transition when a match is found.  The target is symbolic
 * (target = (x & 0xF) + 1) so half the inputs hit, half miss; the lifter
 * must keep both the loop and the early-out branch.
 */
#include <stdio.h>

enum SearchVmPc {
    SR_INIT       = 0,
    SR_INIT_DATA  = 1,
    SR_LOAD_TGT   = 2,
    SR_INIT_IDX   = 3,
    SR_CHECK_END  = 4,
    SR_LOAD_ELT   = 5,
    SR_TEST_EQ    = 6,
    SR_INC_IDX    = 7,
    SR_FOUND      = 8,
    SR_HALT       = 9,
};

__declspec(noinline)
int vm_search_loop_target(int x) {
    int data[8];
    int target = 0;
    int idx    = 0;
    int elt    = 0;
    int result = 0;
    int pc     = SR_INIT;

    while (1) {
        if (pc == SR_INIT) {
            pc = SR_INIT_DATA;
        } else if (pc == SR_INIT_DATA) {
            data[0] = 3;  data[1] = 7;  data[2] = 11; data[3] = 13;
            data[4] = 17; data[5] = 19; data[6] = 23; data[7] = 29;
            pc = SR_LOAD_TGT;
        } else if (pc == SR_LOAD_TGT) {
            target = (x & 0xF) + 1;
            pc = SR_INIT_IDX;
        } else if (pc == SR_INIT_IDX) {
            idx = 0;
            pc = SR_CHECK_END;
        } else if (pc == SR_CHECK_END) {
            if (idx >= 8) { result = 8; pc = SR_HALT; }
            else { pc = SR_LOAD_ELT; }
        } else if (pc == SR_LOAD_ELT) {
            elt = data[idx];
            pc = SR_TEST_EQ;
        } else if (pc == SR_TEST_EQ) {
            pc = (elt == target) ? SR_FOUND : SR_INC_IDX;
        } else if (pc == SR_INC_IDX) {
            idx = idx + 1;
            pc = SR_CHECK_END;
        } else if (pc == SR_FOUND) {
            result = idx;
            pc = SR_HALT;
        } else if (pc == SR_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_search_loop(2)=%d vm_search_loop(15)=%d\n",
           vm_search_loop_target(2), vm_search_loop_target(15));
    return 0;
}
```
