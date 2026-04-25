# vm_ca_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_ca_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_ca_loop.ll`
- **Symbol:** `vm_ca_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_ca_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_ca_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | empty state |
| 2 | RCX=1 | 1 | 1 | 1 | yes | n=0, state=1 |
| 3 | RCX=257 | 2 | 2 | 2 | yes | n=1, state=1: left=2, right=0, state=2 |
| 4 | RCX=513 | 5 | 5 | 5 | yes | n=2 |
| 5 | RCX=769 | 8 | 8 | 8 | yes | n=3 |
| 6 | RCX=1025 | 20 | 20 | 20 | yes | n=4 |
| 7 | RCX=1793 | 128 | 128 | 128 | yes | n=7, state=1 |
| 8 | RCX=256 | 0 | 0 | 0 | yes | n=1, state=0 |
| 9 | RCX=24 | 24 | 24 | 24 | yes | n=0, state=0x18 |
| 10 | RCX=280 | 60 | 60 | 60 | yes | n=1, state=0x18 |
| 11 | RCX=1816 | 24 | 24 | 24 | yes | n=7, state=0x18 |
| 12 | RCX=1877 | 170 | 170 | 170 | yes | n=7, state=0x55 |

## Source

```c
/* PC-state VM that applies a Rule-90-like cellular automaton step to an
 * 8-bit state.
 * Lift target: vm_ca_loop_target.
 * Goal: cover a single-state recurrence whose body combines a left-shift
 * and a right-shift via XOR (state' = (state<<1) ^ (state>>1)).  Distinct
 * from vm_lfsr_loop (single shift + conditional XOR) and vm_rotate_loop
 * (shift+or for rotation): here the linear XOR couples both shift
 * directions every iteration.
 */
#include <stdio.h>

enum CaVmPc {
    CA_LOAD       = 0,
    CA_INIT       = 1,
    CA_CHECK      = 2,
    CA_BODY_LEFT  = 3,
    CA_BODY_RIGHT = 4,
    CA_BODY_XOR   = 5,
    CA_BODY_MASK  = 6,
    CA_BODY_DEC   = 7,
    CA_HALT       = 8,
};

__declspec(noinline)
int vm_ca_loop_target(int x) {
    int state = 0;
    int n     = 0;
    int left  = 0;
    int right = 0;
    int pc    = CA_LOAD;

    while (1) {
        if (pc == CA_LOAD) {
            state = x & 0xFF;
            n = (x >> 8) & 7;
            pc = CA_INIT;
        } else if (pc == CA_INIT) {
            pc = CA_CHECK;
        } else if (pc == CA_CHECK) {
            pc = (n > 0) ? CA_BODY_LEFT : CA_HALT;
        } else if (pc == CA_BODY_LEFT) {
            left = state << 1;
            pc = CA_BODY_RIGHT;
        } else if (pc == CA_BODY_RIGHT) {
            right = (int)((unsigned)state >> 1);
            pc = CA_BODY_XOR;
        } else if (pc == CA_BODY_XOR) {
            state = left ^ right;
            pc = CA_BODY_MASK;
        } else if (pc == CA_BODY_MASK) {
            state = state & 0xFF;
            pc = CA_BODY_DEC;
        } else if (pc == CA_BODY_DEC) {
            n = n - 1;
            pc = CA_CHECK;
        } else if (pc == CA_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_ca_loop(0x701)=%d vm_ca_loop(0x755)=%d\n",
           vm_ca_loop_target(0x701), vm_ca_loop_target(0x755));
    return 0;
}
```
