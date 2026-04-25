# vm_dispatch_table_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dispatch_table_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dispatch_table_loop.ll`
- **Symbol:** `vm_dispatch_table_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dispatch_table_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dispatch_table_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 15 | 15 | 15 | yes | start=0: 0->3->2->1->5->4->7 |
| 2 | RCX=1 | 10 | 10 | 10 | yes | start=1: 1->5->4->7 |
| 3 | RCX=2 | 12 | 12 | 12 | yes | start=2: 2->1->5->4->7 |
| 4 | RCX=3 | 15 | 15 | 15 | yes | start=3: 3->2->1->5->4->7 |
| 5 | RCX=4 | 4 | 4 | 4 | yes | start=4: 4->7 |
| 6 | RCX=5 | 9 | 9 | 9 | yes | start=5: 5->4->7 |
| 7 | RCX=6 | 21 | 21 | 21 | yes | start=6: 6->0->3->2->1->5->4->7 |
| 8 | RCX=7 | 0 | 0 | 0 | yes | start=7: halt immediately |
| 9 | RCX=8 | 15 | 15 | 15 | yes | start=0 again (mask drops bit 3) |
| 10 | RCX=15 | 0 | 0 | 0 | yes | start=7 again after mask |

## Source

```c
/* PC-state VM whose successor PC comes from a stack-resident lookup table.
 * Lift target: vm_dispatch_table_loop_target.
 * Goal: cover a VM whose control flow graph is encoded as data, not code.
 * Each iteration adds the current PC to an accumulator, then advances via
 * NEXT[pc].  The starting PC is symbolic (x & 7); index 7 is the halt state
 * so the loop trip count is data-dependent and hits a different terminator
 * for each input.
 */
#include <stdio.h>

__declspec(noinline)
int vm_dispatch_table_loop_target(int x) {
    int next[8];
    int pc  = 0;
    int acc = 0;

    next[0] = 3;
    next[1] = 5;
    next[2] = 1;
    next[3] = 2;
    next[4] = 7;
    next[5] = 4;
    next[6] = 0;
    next[7] = 7;

    pc = x & 7;

    while (pc != 7) {
        acc = acc + pc;
        pc = next[pc];
    }

    return acc;
}

int main(void) {
    printf("vm_dispatch_table_loop(0)=%d vm_dispatch_table_loop(6)=%d\n",
           vm_dispatch_table_loop_target(0), vm_dispatch_table_loop_target(6));
    return 0;
}
```
