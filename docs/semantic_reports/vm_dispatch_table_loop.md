# vm_dispatch_table_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_dispatch_table_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dispatch_table_loop.ll`
- **Symbol:** `vm_dispatch_table_loop_target`
- **IR size:** 65 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 15 | 15 | pass | start=0: 0->3->2->1->5->4->7 |
| 2 | RCX=1 | 10 | 10 | pass | start=1: 1->5->4->7 |
| 3 | RCX=2 | 12 | 12 | pass | start=2: 2->1->5->4->7 |
| 4 | RCX=3 | 15 | 15 | pass | start=3: 3->2->1->5->4->7 |
| 5 | RCX=4 | 4 | 4 | pass | start=4: 4->7 |
| 6 | RCX=5 | 9 | 9 | pass | start=5: 5->4->7 |
| 7 | RCX=6 | 21 | 21 | pass | start=6: 6->0->3->2->1->5->4->7 |
| 8 | RCX=7 | 0 | 0 | pass | start=7: halt immediately |
| 9 | RCX=8 | 15 | 15 | pass | start=0 again (mask drops bit 3) |
| 10 | RCX=15 | 0 | 0 | pass | start=7 again after mask |

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
