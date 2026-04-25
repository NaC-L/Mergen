# vm_branchy_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/vm_branchy_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_branchy_loop.ll`
- **Symbol:** `vm_branchy_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_branchy_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_branchy_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=0: no iterations |
| 2 | RCX=1 | 0 | 0 | 0 | yes | limit=1: only i=0 (even) |
| 3 | RCX=2 | 1 | 1 | 1 | yes | limit=2: i=1 is odd |
| 4 | RCX=5 | 2 | 2 | 2 | yes | limit=5: odds {1,3} |
| 5 | RCX=10 | 5 | 5 | 5 | yes | limit=10: odds {1,3,5,7,9} |
| 6 | RCX=15 | 7 | 7 | 7 | yes | limit=15: odds 1..13 |
| 7 | RCX=16 | 0 | 0 | 0 | yes | limit=0 (mask drops bit 4) |
| 8 | RCX=31 | 7 | 7 | 7 | yes | limit=15 again after mask |

## Source

```c
/* PC-state VM with a conditional branch inside the loop body.
 * Lift target: vm_branchy_loop_target.
 * Goal: keep a VM-shaped dispatcher with a real loop AND a data-dependent
 * branch in the loop body (parity test on the loop induction variable).
 * Counts how many odd values exist in [0, limit) where limit = x & 0xF.
 */
#include <stdio.h>

enum BranchVmPc {
    BV_INIT        = 0,
    BV_LOAD_LIMIT  = 1,
    BV_CHECK_LIMIT = 2,
    BV_TEST_PARITY = 3,
    BV_INC_COUNT   = 4,
    BV_INC_INDEX   = 5,
    BV_HALT        = 6,
};

__declspec(noinline)
int vm_branchy_loop_target(int x) {
    int i      = 0;
    int count  = 0;
    int limit  = 0;
    int parity = 0;
    int pc     = BV_LOAD_LIMIT;

    while (1) {
        if (pc == BV_LOAD_LIMIT) {
            i = 0;
            count = 0;
            limit = x & 0xF;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_CHECK_LIMIT) {
            pc = (i < limit) ? BV_TEST_PARITY : BV_HALT;
        } else if (pc == BV_TEST_PARITY) {
            parity = i & 1;
            pc = (parity != 0) ? BV_INC_COUNT : BV_INC_INDEX;
        } else if (pc == BV_INC_COUNT) {
            count = count + 1;
            pc = BV_INC_INDEX;
        } else if (pc == BV_INC_INDEX) {
            i = i + 1;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_branchy_loop(10)=%d vm_branchy_loop(15)=%d\n",
           vm_branchy_loop_target(10), vm_branchy_loop_target(15));
    return 0;
}
```
