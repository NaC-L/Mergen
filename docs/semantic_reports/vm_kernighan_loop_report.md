# vm_kernighan_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_kernighan_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_kernighan_loop.ll`
- **Symbol:** `vm_kernighan_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_kernighan_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_kernighan_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | v=0: 0 trips |
| 2 | RCX=1 | 1 | 1 | 1 | yes | v=1 |
| 3 | RCX=3 | 2 | 2 | 2 | yes | v=0x03 |
| 4 | RCX=7 | 3 | 3 | 3 | yes | v=0x07 |
| 5 | RCX=85 | 4 | 4 | 4 | yes | 0x55: 4 bits set |
| 6 | RCX=170 | 4 | 4 | 4 | yes | 0xAA: 4 bits set |
| 7 | RCX=65535 | 16 | 16 | 16 | yes | all 16 bits: 16 trips |
| 8 | RCX=256 | 1 | 1 | 1 | yes | 0x100: single bit |
| 9 | RCX=4660 | 5 | 5 | 5 | yes | 0x1234: 5 bits |
| 10 | RCX=32768 | 1 | 1 | 1 | yes | 0x8000 |
| 11 | RCX=32769 | 2 | 2 | 2 | yes | 0x8001 |
| 12 | RCX=65534 | 15 | 15 | 15 | yes | 0xFFFE |

## Source

```c
/* PC-state VM running Brian Kernighan's popcount trick.
 * Lift target: vm_kernighan_loop_target.
 * Goal: cover a non-counted loop whose body uses v &= v - 1 to clear the
 * lowest set bit, terminating when v reaches zero.  Distinct from
 * vm_popcount_loop (which examines one bit per iteration via shift-and-and):
 * here the trip count equals the popcount itself, and each iteration
 * subtracts one then ANDs.
 */
#include <stdio.h>

enum KnVmPc {
    KN_LOAD       = 0,
    KN_INIT       = 1,
    KN_CHECK      = 2,
    KN_BODY_SUB   = 3,
    KN_BODY_AND   = 4,
    KN_BODY_INC   = 5,
    KN_HALT       = 6,
};

__declspec(noinline)
int vm_kernighan_loop_target(int x) {
    int v     = 0;
    int count = 0;
    int sub   = 0;
    int pc    = KN_LOAD;

    while (1) {
        if (pc == KN_LOAD) {
            v = x & 0xFFFF;
            count = 0;
            pc = KN_INIT;
        } else if (pc == KN_INIT) {
            pc = KN_CHECK;
        } else if (pc == KN_CHECK) {
            pc = (v != 0) ? KN_BODY_SUB : KN_HALT;
        } else if (pc == KN_BODY_SUB) {
            sub = v - 1;
            pc = KN_BODY_AND;
        } else if (pc == KN_BODY_AND) {
            v = v & sub;
            pc = KN_BODY_INC;
        } else if (pc == KN_BODY_INC) {
            count = count + 1;
            pc = KN_CHECK;
        } else if (pc == KN_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_kernighan_loop(0xFFFF)=%d vm_kernighan_loop(0x1234)=%d\n",
           vm_kernighan_loop_target(0xFFFF), vm_kernighan_loop_target(0x1234));
    return 0;
}
```
