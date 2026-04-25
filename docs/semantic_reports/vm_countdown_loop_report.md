# vm_countdown_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/vm_countdown_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_countdown_loop.ll`
- **Symbol:** `vm_countdown_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_countdown_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_countdown_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | count=0: empty sum |
| 2 | RCX=1 | 1 | 1 | 1 | yes | count=1: T(1) |
| 3 | RCX=2 | 3 | 3 | 3 | yes | count=2: T(2) |
| 4 | RCX=5 | 15 | 15 | 15 | yes | count=5: T(5) |
| 5 | RCX=10 | 55 | 55 | 55 | yes | count=10: T(10) |
| 6 | RCX=15 | 120 | 120 | 120 | yes | count=15: T(15) |
| 7 | RCX=16 | 0 | 0 | 0 | yes | count=0 again (mask drops bit 4) |
| 8 | RCX=255 | 120 | 120 | 120 | yes | count=15 again after mask |

## Source

```c
/* PC-state VM with a reverse-induction counted loop.
 * Lift target: vm_countdown_loop_target.
 * Goal: exercise loop detection for a loop whose induction variable *decreases*
 * and whose bound is a symbolic countdown rather than a rising compare.
 * Computes the triangular number sum(1..n) where n = x & 0xF, but builds it
 * by counting down from n to 1 instead of up.
 */
#include <stdio.h>

enum CdVmPc {
    CD_INIT       = 0,
    CD_LOAD_COUNT = 1,
    CD_INIT_SUM   = 2,
    CD_CHECK      = 3,
    CD_BODY_ADD   = 4,
    CD_BODY_DEC   = 5,
    CD_HALT       = 6,
};

__declspec(noinline)
int vm_countdown_loop_target(int x) {
    int count = 0;
    int sum   = 0;
    int pc    = CD_INIT;

    while (1) {
        if (pc == CD_INIT) {
            pc = CD_LOAD_COUNT;
        } else if (pc == CD_LOAD_COUNT) {
            count = x & 0xF;
            pc = CD_INIT_SUM;
        } else if (pc == CD_INIT_SUM) {
            sum = 0;
            pc = CD_CHECK;
        } else if (pc == CD_CHECK) {
            pc = (count > 0) ? CD_BODY_ADD : CD_HALT;
        } else if (pc == CD_BODY_ADD) {
            sum = sum + count;
            pc = CD_BODY_DEC;
        } else if (pc == CD_BODY_DEC) {
            count = count - 1;
            pc = CD_CHECK;
        } else if (pc == CD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_countdown_loop(10)=%d vm_countdown_loop(15)=%d\n",
           vm_countdown_loop_target(10), vm_countdown_loop_target(15));
    return 0;
}
```
