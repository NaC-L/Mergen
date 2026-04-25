# vm_lcg_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_lcg_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_lcg_loop.ll`
- **Symbol:** `vm_lcg_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_lcg_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_lcg_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | n=0: state stays 1 |
| 2 | RCX=1 | 9 | 9 | 9 | yes | n=1, key=1: 9 |
| 3 | RCX=2 | 55 | 55 | 55 | yes | n=2, key=2 |
| 4 | RCX=5 | 157 | 157 | 157 | yes | n=5, key=5 |
| 5 | RCX=7 | 27 | 27 | 27 | yes | n=7, key=7 |
| 6 | RCX=10 | 159 | 159 | 159 | yes | n=10, key=10 |
| 7 | RCX=15 | 131 | 131 | 131 | yes | n=15, key=15 |
| 8 | RCX=16 | 1 | 1 | 1 | yes | n=0 again (mask drops bit 4 of n) |
| 9 | RCX=100 | 53 | 53 | 53 | yes | n=4, key=100 |
| 10 | RCX=255 | 83 | 83 | 83 | yes | n=15, key=0xFF |

## Source

```c
/* PC-state VM running an LCG-style mixed multiply-and-mask recurrence.
 * Lift target: vm_lcg_loop_target.
 * Goal: cover a single-state recurrence whose body mixes multiplication,
 * addition, and a bitmask in one update step:
 *   state = (state * 5 + key + 3) & 0xFF
 * Both the key and the iteration count are derived from x so neither the
 * loop bound nor the recurrence can be folded.
 */
#include <stdio.h>

enum LcgVmPc {
    LG_INIT       = 0,
    LG_LOAD_KEY   = 1,
    LG_LOAD_N     = 2,
    LG_INIT_STATE = 3,
    LG_CHECK      = 4,
    LG_BODY_MUL   = 5,
    LG_BODY_ADD   = 6,
    LG_BODY_MASK  = 7,
    LG_BODY_DEC   = 8,
    LG_HALT       = 9,
};

__declspec(noinline)
int vm_lcg_loop_target(int x) {
    int key   = 0;
    int n     = 0;
    int state = 0;
    int tmp   = 0;
    int pc    = LG_INIT;

    while (1) {
        if (pc == LG_INIT) {
            pc = LG_LOAD_KEY;
        } else if (pc == LG_LOAD_KEY) {
            key = x & 0xFF;
            pc = LG_LOAD_N;
        } else if (pc == LG_LOAD_N) {
            n = x & 0xF;
            pc = LG_INIT_STATE;
        } else if (pc == LG_INIT_STATE) {
            state = 1;
            pc = LG_CHECK;
        } else if (pc == LG_CHECK) {
            pc = (n > 0) ? LG_BODY_MUL : LG_HALT;
        } else if (pc == LG_BODY_MUL) {
            tmp = state * 5;
            pc = LG_BODY_ADD;
        } else if (pc == LG_BODY_ADD) {
            tmp = tmp + key + 3;
            pc = LG_BODY_MASK;
        } else if (pc == LG_BODY_MASK) {
            state = tmp & 0xFF;
            pc = LG_BODY_DEC;
        } else if (pc == LG_BODY_DEC) {
            n = n - 1;
            pc = LG_CHECK;
        } else if (pc == LG_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lcg_loop(7)=%d vm_lcg_loop(255)=%d\n",
           vm_lcg_loop_target(7), vm_lcg_loop_target(255));
    return 0;
}
```
