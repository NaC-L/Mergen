# vm_hamming_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_hamming_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_hamming_loop.ll`
- **Symbol:** `vm_hamming_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_hamming_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_hamming_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | a=0,b=0: hamming 0 |
| 2 | RCX=18 | 2 | 2 | 2 | yes | a=2,b=1: hamming 2 |
| 3 | RCX=51 | 0 | 0 | 0 | yes | a=3,b=3: hamming 0 |
| 4 | RCX=85 | 0 | 0 | 0 | yes | a=5,b=5: hamming 0 |
| 5 | RCX=170 | 0 | 0 | 0 | yes | a=10,b=10: hamming 0 |
| 6 | RCX=240 | 4 | 4 | 4 | yes | a=0,b=15: hamming 4 |
| 7 | RCX=255 | 0 | 0 | 0 | yes | a=15,b=15: hamming 0 |
| 8 | RCX=1 | 1 | 1 | 1 | yes | a=1,b=0: hamming 1 |
| 9 | RCX=7 | 3 | 3 | 3 | yes | a=7,b=0: hamming 3 |
| 10 | RCX=128 | 1 | 1 | 1 | yes | a=0,b=8: hamming 1 |

## Source

```c
/* PC-state VM computing the Hamming distance between two 4-bit operands.
 * Lift target: vm_hamming_loop_target.
 * Goal: cover a bitwise loop with TWO symbolic operands (a = x & 0xF,
 * b = (x >> 4) & 0xF) where the body XORs and pop-counts.  The dispatcher
 * uses the dual_counter init-state pattern (explicit i=0/dist=0 in the
 * first dispatcher state) so the lifter threads initial values through the
 * loop phi correctly even on the empty-loop path (a == b).
 */
#include <stdio.h>

enum HamVmPc {
    HV_INIT      = 0,
    HV_LOAD      = 1,
    HV_CHECK     = 2,
    HV_BODY_BIT  = 3,
    HV_BODY_ADD  = 4,
    HV_BODY_SHR  = 5,
    HV_HALT      = 6,
};

__declspec(noinline)
int vm_hamming_loop_target(int x) {
    int a    = 0;
    int b    = 0;
    int v    = 0;
    int dist = 0;
    int bit  = 0;
    int pc   = HV_LOAD;

    while (1) {
        if (pc == HV_LOAD) {
            a = x & 0xF;
            b = (x >> 4) & 0xF;
            v = a ^ b;
            dist = 0;
            pc = HV_CHECK;
        } else if (pc == HV_CHECK) {
            pc = (v != 0) ? HV_BODY_BIT : HV_HALT;
        } else if (pc == HV_BODY_BIT) {
            bit = v & 1;
            pc = HV_BODY_ADD;
        } else if (pc == HV_BODY_ADD) {
            dist = dist + bit;
            pc = HV_BODY_SHR;
        } else if (pc == HV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = HV_CHECK;
        } else if (pc == HV_HALT) {
            return dist;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_hamming_loop(0x12)=%d vm_hamming_loop(0xF0)=%d\n",
           vm_hamming_loop_target(0x12), vm_hamming_loop_target(0xF0));
    return 0;
}
```
