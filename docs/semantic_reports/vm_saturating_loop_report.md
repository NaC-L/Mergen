# vm_saturating_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_saturating_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_saturating_loop.ll`
- **Symbol:** `vm_saturating_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_saturating_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_saturating_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | n=1 |
| 3 | RCX=2 | 1 | 1 | 1 | yes | n=2 |
| 4 | RCX=5 | 10 | 10 | 10 | yes | n=5: 0+1+2+3+4 |
| 5 | RCX=10 | 45 | 45 | 45 | yes | n=10: 0..9 sum 45 |
| 6 | RCX=14 | 91 | 91 | 91 | yes | n=14: just below clamp |
| 7 | RCX=15 | 100 | 100 | 100 | yes | n=15: 105 -> clamp |
| 8 | RCX=20 | 100 | 100 | 100 | yes | n=20: clamped |
| 9 | RCX=128 | 100 | 100 | 100 | yes | n=128: clamped |
| 10 | RCX=255 | 100 | 100 | 100 | yes | n=255: clamped |

## Source

```c
/* PC-state VM running a counted sum loop with saturation clamp.
 * Lift target: vm_saturating_loop_target.
 * Goal: cover a loop body that performs an add followed by a value-clamp
 * (select on overflow), distinct from the pure additive sum loops which
 * grow unbounded.  Trip count n = x & 0xFF spans the full clamp boundary.
 */
#include <stdio.h>

enum SatVmPc {
    ST_LOAD     = 0,
    ST_INIT     = 1,
    ST_CHECK    = 2,
    ST_BODY_ADD = 3,
    ST_BODY_CLAMP = 4,
    ST_BODY_INC = 5,
    ST_HALT     = 6,
};

__declspec(noinline)
int vm_saturating_loop_target(int x) {
    int n   = 0;
    int i   = 0;
    int sum = 0;
    int pc  = ST_LOAD;

    while (1) {
        if (pc == ST_LOAD) {
            n = x & 0xFF;
            i = 0;
            sum = 0;
            pc = ST_INIT;
        } else if (pc == ST_INIT) {
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY_ADD : ST_HALT;
        } else if (pc == ST_BODY_ADD) {
            sum = sum + i;
            pc = ST_BODY_CLAMP;
        } else if (pc == ST_BODY_CLAMP) {
            if (sum > 100) {
                sum = 100;
            }
            pc = ST_BODY_INC;
        } else if (pc == ST_BODY_INC) {
            i = i + 1;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_saturating_loop(10)=%d vm_saturating_loop(20)=%d\n",
           vm_saturating_loop_target(10), vm_saturating_loop_target(20));
    return 0;
}
```
