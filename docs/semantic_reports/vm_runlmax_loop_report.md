# vm_runlmax_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_runlmax_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_runlmax_loop.ll`
- **Symbol:** `vm_runlmax_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_runlmax_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_runlmax_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero |
| 2 | RCX=1 | 1 | 1 | 1 | yes | single bit |
| 3 | RCX=3 | 2 | 2 | 2 | yes | 0x03: pair |
| 4 | RCX=255 | 8 | 8 | 8 | yes | 0xFF: 8 ones |
| 5 | RCX=65535 | 16 | 16 | 16 | yes | all 16 ones |
| 6 | RCX=61680 | 4 | 4 | 4 | yes | 0xF0F0: max run 4 |
| 7 | RCX=85 | 1 | 1 | 1 | yes | 0x55: alternating |
| 8 | RCX=102 | 2 | 2 | 2 | yes | 0x66: max 2 |
| 9 | RCX=504 | 6 | 6 | 6 | yes | 0x1F8: max 6 |
| 10 | RCX=4660 | 2 | 2 | 2 | yes | 0x1234 |
| 11 | RCX=52428 | 2 | 2 | 2 | yes | 0xCCCC: pairs |
| 12 | RCX=32769 | 1 | 1 | 1 | yes | 0x8001: two isolated |

## Source

```c
/* PC-state VM that finds the length of the longest run of consecutive 1-bits
 * in the low 16 bits of x.
 * Lift target: vm_runlmax_loop_target.
 * Goal: cover a loop body that maintains TWO state vars (current run length
 * and max so far) using the always-write recipe:
 *   cur = (cur + 1) * bit       // 0 resets, 1 extends
 *   max = (cur > max) ? cur : max  // always written
 */
#include <stdio.h>

enum RmVmPc {
    RM_LOAD       = 0,
    RM_INIT       = 1,
    RM_CHECK      = 2,
    RM_BODY_BIT   = 3,
    RM_BODY_CUR   = 4,
    RM_BODY_MAX   = 5,
    RM_BODY_INC   = 6,
    RM_HALT       = 7,
};

__declspec(noinline)
int vm_runlmax_loop_target(int x) {
    int idx   = 0;
    int cur   = 0;
    int mx    = 0;
    int bit   = 0;
    int next  = 0;
    int pc    = RM_LOAD;

    while (1) {
        if (pc == RM_LOAD) {
            idx = 0;
            cur = 0;
            mx = 0;
            pc = RM_INIT;
        } else if (pc == RM_INIT) {
            pc = RM_CHECK;
        } else if (pc == RM_CHECK) {
            pc = (idx < 16) ? RM_BODY_BIT : RM_HALT;
        } else if (pc == RM_BODY_BIT) {
            bit = (x >> idx) & 1;
            pc = RM_BODY_CUR;
        } else if (pc == RM_BODY_CUR) {
            cur = (cur + 1) * bit;
            pc = RM_BODY_MAX;
        } else if (pc == RM_BODY_MAX) {
            next = (cur > mx) ? cur : mx;
            mx = next;
            pc = RM_BODY_INC;
        } else if (pc == RM_BODY_INC) {
            idx = idx + 1;
            pc = RM_CHECK;
        } else if (pc == RM_HALT) {
            return mx;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_runlmax_loop(0xFFFF)=%d vm_runlmax_loop(0x1F8)=%d\n",
           vm_runlmax_loop_target(0xFFFF), vm_runlmax_loop_target(0x1F8));
    return 0;
}
```
