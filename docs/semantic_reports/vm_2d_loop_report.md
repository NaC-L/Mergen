# vm_2d_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_2d_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_2d_loop.ll`
- **Symbol:** `vm_2d_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_2d_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_2d_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1212 | 1212 | 1212 | yes | seed=0: diag=0+4+8=12, anti=2+4+6=12 |
| 2 | RCX=1 | 1515 | 1515 | 1515 | yes | seed=1 |
| 3 | RCX=5 | 2727 | 2727 | 2727 | yes | seed=5 |
| 4 | RCX=7 | 3333 | 3333 | 3333 | yes | seed=7 |
| 5 | RCX=10 | 4242 | 4242 | 4242 | yes | 0xA |
| 6 | RCX=15 | 5757 | 5757 | 5757 | yes | 0xF |
| 7 | RCX=16 | 1212 | 1212 | 1212 | yes | 0x10: seed=0 (mask) |
| 8 | RCX=51966 | 5454 | 5454 | 5454 | yes | 0xCAFE: seed=14 |
| 9 | RCX=74565 | 2727 | 2727 | 2727 | yes | 0x12345: seed=5 |
| 10 | RCX=43981 | 5151 | 5151 | 5151 | yes | 0xABCD: seed=13 |

## Source

```c
/* PC-state VM that fills a 3x3 stack grid via nested loops, then sums
 * the main and anti diagonals.
 * Lift target: vm_2d_loop_target.
 * Goal: cover 2D-style indexing (grid[i][j] flattens to grid[i*3+j]) with
 * nested PC-state loops, and a tail compute that pulls fixed-offset
 * elements from the same array.
 */
#include <stdio.h>

enum TdVmPc {
    TD_LOAD       = 0,
    TD_OUTER_INIT = 1,
    TD_OUTER_CHECK = 2,
    TD_INNER_INIT = 3,
    TD_INNER_CHECK = 4,
    TD_FILL_BODY  = 5,
    TD_INNER_INC  = 6,
    TD_OUTER_INC  = 7,
    TD_DIAG       = 8,
    TD_ANTI       = 9,
    TD_PACK       = 10,
    TD_HALT       = 11,
};

__declspec(noinline)
int vm_2d_loop_target(int x) {
    int grid[9];
    int seed = 0;
    int i    = 0;
    int j    = 0;
    int diag = 0;
    int anti = 0;
    int result = 0;
    int pc   = TD_LOAD;

    while (1) {
        if (pc == TD_LOAD) {
            seed = x & 0xF;
            pc = TD_OUTER_INIT;
        } else if (pc == TD_OUTER_INIT) {
            i = 0;
            pc = TD_OUTER_CHECK;
        } else if (pc == TD_OUTER_CHECK) {
            pc = (i < 3) ? TD_INNER_INIT : TD_DIAG;
        } else if (pc == TD_INNER_INIT) {
            j = 0;
            pc = TD_INNER_CHECK;
        } else if (pc == TD_INNER_CHECK) {
            pc = (j < 3) ? TD_FILL_BODY : TD_OUTER_INC;
        } else if (pc == TD_FILL_BODY) {
            grid[i * 3 + j] = (i * 3 + j + seed) & 0x1F;
            pc = TD_INNER_INC;
        } else if (pc == TD_INNER_INC) {
            j = j + 1;
            pc = TD_INNER_CHECK;
        } else if (pc == TD_OUTER_INC) {
            i = i + 1;
            pc = TD_OUTER_CHECK;
        } else if (pc == TD_DIAG) {
            diag = grid[0] + grid[4] + grid[8];
            pc = TD_ANTI;
        } else if (pc == TD_ANTI) {
            anti = grid[2] + grid[4] + grid[6];
            pc = TD_PACK;
        } else if (pc == TD_PACK) {
            result = diag * 100 + anti;
            pc = TD_HALT;
        } else if (pc == TD_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_2d_loop(0xA)=%d vm_2d_loop(0xCAFE)=%d\n",
           vm_2d_loop_target(0xA),
           vm_2d_loop_target(0xCAFE));
    return 0;
}
```
