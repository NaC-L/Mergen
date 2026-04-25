# vm_popcount_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_popcount_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_popcount_loop.ll`
- **Symbol:** `vm_popcount_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_popcount_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_popcount_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | v=0: halt immediately |
| 2 | RCX=1 | 1 | 1 | 1 | yes | v=0x01: 1 bit |
| 3 | RCX=3 | 2 | 2 | 2 | yes | v=0x03: 2 bits |
| 4 | RCX=7 | 3 | 3 | 3 | yes | v=0x07: 3 bits |
| 5 | RCX=15 | 4 | 4 | 4 | yes | v=0x0F: 4 bits |
| 6 | RCX=170 | 4 | 4 | 4 | yes | v=0xAA: alternating bits |
| 7 | RCX=85 | 4 | 4 | 4 | yes | v=0x55: alternating bits |
| 8 | RCX=255 | 8 | 8 | 8 | yes | v=0xFF: all bits set |
| 9 | RCX=256 | 0 | 0 | 0 | yes | v=0 again (mask clears bit 8) |
| 10 | RCX=257 | 1 | 1 | 1 | yes | v=0x01 again after mask |

## Source

```c
/* PC-state VM that counts set bits via a shift+and+add loop.
 * Lift target: vm_popcount_loop_target.
 * Goal: cover a bitwise-driven loop whose termination test is "value reached
 * zero" rather than a counted compare.  Operates on the low 8 bits of x so
 * the trip count is bounded but symbolic.
 */
#include <stdio.h>

enum PopVmPc {
    PV_INIT      = 0,
    PV_LOAD_VAL  = 1,
    PV_INIT_CNT  = 2,
    PV_CHECK     = 3,
    PV_BODY_BIT  = 4,
    PV_BODY_ADD  = 5,
    PV_BODY_SHR  = 6,
    PV_HALT      = 7,
};

__declspec(noinline)
int vm_popcount_loop_target(int x) {
    int v   = 0;
    int cnt = 0;
    int bit = 0;
    int pc  = PV_INIT;

    while (1) {
        if (pc == PV_INIT) {
            pc = PV_LOAD_VAL;
        } else if (pc == PV_LOAD_VAL) {
            v = x & 0xFF;
            pc = PV_INIT_CNT;
        } else if (pc == PV_INIT_CNT) {
            cnt = 0;
            pc = PV_CHECK;
        } else if (pc == PV_CHECK) {
            pc = (v != 0) ? PV_BODY_BIT : PV_HALT;
        } else if (pc == PV_BODY_BIT) {
            bit = v & 1;
            pc = PV_BODY_ADD;
        } else if (pc == PV_BODY_ADD) {
            cnt = cnt + bit;
            pc = PV_BODY_SHR;
        } else if (pc == PV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = PV_CHECK;
        } else if (pc == PV_HALT) {
            return cnt;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popcount_loop(0xAA)=%d vm_popcount_loop(0xFF)=%d\n",
           vm_popcount_loop_target(0xAA), vm_popcount_loop_target(0xFF));
    return 0;
}
```
