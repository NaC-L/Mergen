# vm_runlength_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 13/13 equivalent
- **Source:** `testcases/rewrite_smoke/vm_runlength_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_runlength_loop.ll`
- **Symbol:** `vm_runlength_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_runlength_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_runlength_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | no runs |
| 2 | RCX=1 | 1 | 1 | 1 | yes | single 1 bit |
| 3 | RCX=3 | 1 | 1 | 1 | yes | contiguous 11 |
| 4 | RCX=5 | 2 | 2 | 2 | yes | 0101: 2 runs |
| 5 | RCX=7 | 1 | 1 | 1 | yes | contiguous 111 |
| 6 | RCX=65535 | 1 | 1 | 1 | yes | all 16 ones: 1 run |
| 7 | RCX=21845 | 8 | 8 | 8 | yes | 0x5555: 8 isolated 1s |
| 8 | RCX=43690 | 8 | 8 | 8 | yes | 0xAAAA: 8 isolated 1s |
| 9 | RCX=52428 | 4 | 4 | 4 | yes | 0xCCCC: 4 pairs |
| 10 | RCX=3855 | 2 | 2 | 2 | yes | 0x0F0F: 2 runs of 4 |
| 11 | RCX=61680 | 2 | 2 | 2 | yes | 0xF0F0: 2 runs of 4 |
| 12 | RCX=4660 | 4 | 4 | 4 | yes | 0x1234: 4 runs |
| 13 | RCX=43520 | 4 | 4 | 4 | yes | 0xAA00: 4 isolated 1s in upper byte |

## Source

```c
/* PC-state VM that counts distinct runs of 1-bits in the low 16 bits of x.
 * Lift target: vm_runlength_loop_target.
 * Goal: cover a bitwise loop body with a sequential dependency on the
 * previous iteration's bit (run-detection: 1->0 / 0->1 transitions).  Body
 * uses the always-write recipe (runs += start_of_run_predicate) to avoid
 * the multi-counter phi-undef bug.
 */
#include <stdio.h>

enum RlVmPc {
    RL_LOAD       = 0,
    RL_INIT       = 1,
    RL_CHECK      = 2,
    RL_BODY_BIT   = 3,
    RL_BODY_START = 4,
    RL_BODY_ADD   = 5,
    RL_BODY_PREV  = 6,
    RL_BODY_INC   = 7,
    RL_HALT       = 8,
};

__declspec(noinline)
int vm_runlength_loop_target(int x) {
    int idx   = 0;
    int prev  = 0;
    int runs  = 0;
    int bit   = 0;
    int start = 0;
    int pc    = RL_LOAD;

    while (1) {
        if (pc == RL_LOAD) {
            idx = 0;
            prev = 0;
            runs = 0;
            pc = RL_INIT;
        } else if (pc == RL_INIT) {
            pc = RL_CHECK;
        } else if (pc == RL_CHECK) {
            pc = (idx < 16) ? RL_BODY_BIT : RL_HALT;
        } else if (pc == RL_BODY_BIT) {
            bit = (x >> idx) & 1;
            pc = RL_BODY_START;
        } else if (pc == RL_BODY_START) {
            start = bit & (~prev) & 1;
            pc = RL_BODY_ADD;
        } else if (pc == RL_BODY_ADD) {
            runs = runs + start;
            pc = RL_BODY_PREV;
        } else if (pc == RL_BODY_PREV) {
            prev = bit;
            pc = RL_BODY_INC;
        } else if (pc == RL_BODY_INC) {
            idx = idx + 1;
            pc = RL_CHECK;
        } else if (pc == RL_HALT) {
            return runs;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_runlength_loop(0x1234)=%d vm_runlength_loop(0x5555)=%d\n",
           vm_runlength_loop_target(0x1234), vm_runlength_loop_target(0x5555));
    return 0;
}
```
