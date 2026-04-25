# vm_nested_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_nested_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_nested_loop.ll`
- **Symbol:** `vm_nested_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_nested_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_nested_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | a=0,b=0: no iterations |
| 2 | RCX=1 | 0 | 0 | 0 | yes | a=1,b=0: inner never runs |
| 3 | RCX=2 | 0 | 0 | 0 | yes | a=2,b=0: inner never runs |
| 4 | RCX=4 | 0 | 0 | 0 | yes | a=0,b=1: outer never runs |
| 5 | RCX=5 | 0 | 0 | 0 | yes | a=1,b=1: one cell, 0+0 |
| 6 | RCX=7 | 3 | 3 | 3 | yes | a=3,b=1: 0+1+2 |
| 7 | RCX=10 | 4 | 4 | 4 | yes | a=2,b=2: (0+1)+(1+2)=4 |
| 8 | RCX=11 | 9 | 9 | 9 | yes | a=3,b=2: 1+3+5=9 |
| 9 | RCX=15 | 18 | 18 | 18 | yes | a=3,b=3: 3+6+9=18 |
| 10 | RCX=255 | 18 | 18 | 18 | yes | high bits ignored: a=3,b=3 |

## Source

```c
/* PC-state VM with two nested counted loops, both encoded in interpreter state.
 * Lift target: vm_nested_loop_target.
 * Goal: stress loop generalization by keeping the outer and inner loops as
 * distinct PC cycles rather than native control flow.  Both bounds are
 * symbolic (a = x & 3, b = (x>>2) & 3), and the inner body computes
 * acc += i + j across the full grid.
 */
#include <stdio.h>

enum NestedVmPc {
    NV_INIT        = 0,
    NV_OUTER_CHECK = 1,
    NV_INNER_INIT  = 2,
    NV_INNER_CHECK = 3,
    NV_INNER_BODY  = 4,
    NV_INNER_INC   = 5,
    NV_OUTER_INC   = 6,
    NV_HALT        = 7,
};

__declspec(noinline)
int vm_nested_loop_target(int x) {
    int a   = x & 3;
    int b   = (x >> 2) & 3;
    int i   = 0;
    int j   = 0;
    int acc = 0;
    int pc  = NV_INIT;

    while (1) {
        if (pc == NV_INIT) {
            i = 0;
            acc = 0;
            pc = NV_OUTER_CHECK;
        } else if (pc == NV_OUTER_CHECK) {
            pc = (i < a) ? NV_INNER_INIT : NV_HALT;
        } else if (pc == NV_INNER_INIT) {
            j = 0;
            pc = NV_INNER_CHECK;
        } else if (pc == NV_INNER_CHECK) {
            pc = (j < b) ? NV_INNER_BODY : NV_OUTER_INC;
        } else if (pc == NV_INNER_BODY) {
            acc = acc + i + j;
            pc = NV_INNER_INC;
        } else if (pc == NV_INNER_INC) {
            j = j + 1;
            pc = NV_INNER_CHECK;
        } else if (pc == NV_OUTER_INC) {
            i = i + 1;
            pc = NV_OUTER_CHECK;
        } else if (pc == NV_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_nested_loop(15)=%d vm_nested_loop(11)=%d\n",
           vm_nested_loop_target(15), vm_nested_loop_target(11));
    return 0;
}
```
