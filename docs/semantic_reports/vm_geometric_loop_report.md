# vm_geometric_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_geometric_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_geometric_loop.ll`
- **Symbol:** `vm_geometric_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_geometric_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_geometric_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | target=1: no doubling |
| 2 | RCX=1 | 0 | 0 | 0 | yes | target=1 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | target=3: 1->2->4 |
| 4 | RCX=4 | 3 | 3 | 3 | yes | target=5: 1->2->4->8 |
| 5 | RCX=8 | 4 | 4 | 4 | yes | target=9 |
| 6 | RCX=15 | 4 | 4 | 4 | yes | target=15 |
| 7 | RCX=16 | 5 | 5 | 5 | yes | target=17 |
| 8 | RCX=64 | 7 | 7 | 7 | yes | target=65 |
| 9 | RCX=128 | 8 | 8 | 8 | yes | target=129 |
| 10 | RCX=255 | 8 | 8 | 8 | yes | target=255 |

## Source

```c
/* PC-state VM running a geometric (log2-style) doubling loop.
 * Lift target: vm_geometric_loop_target.
 * Goal: cover a loop where the induction variable grows multiplicatively
 * (r *= 2) while a counter grows linearly, terminating when r reaches a
 * symbolic target.  Different recurrence shape from the additive sum
 * loops and the multiplicative factorial loop (where the loop bound is
 * symbolic, not the value).
 */
#include <stdio.h>

enum GeoVmPc {
    GE_LOAD     = 0,
    GE_INIT     = 1,
    GE_CHECK    = 2,
    GE_BODY_DBL = 3,
    GE_BODY_INC = 4,
    GE_HALT     = 5,
};

__declspec(noinline)
int vm_geometric_loop_target(int x) {
    int target = 0;
    int r      = 0;
    int count  = 0;
    int pc     = GE_LOAD;

    while (1) {
        if (pc == GE_LOAD) {
            target = (x & 0xFF) | 1;
            r = 1;
            count = 0;
            pc = GE_INIT;
        } else if (pc == GE_INIT) {
            pc = GE_CHECK;
        } else if (pc == GE_CHECK) {
            pc = (r < target) ? GE_BODY_DBL : GE_HALT;
        } else if (pc == GE_BODY_DBL) {
            r = r * 2;
            pc = GE_BODY_INC;
        } else if (pc == GE_BODY_INC) {
            count = count + 1;
            pc = GE_CHECK;
        } else if (pc == GE_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_geometric_loop(15)=%d vm_geometric_loop(128)=%d\n",
           vm_geometric_loop_target(15), vm_geometric_loop_target(128));
    return 0;
}
```
