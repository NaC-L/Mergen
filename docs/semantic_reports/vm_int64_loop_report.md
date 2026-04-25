# vm_int64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_int64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_int64_loop.ll`
- **Symbol:** `vm_int64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_int64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_int64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, acc=0*31+0=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=2: 0*31+0=0; 0*31+1=1 |
| 3 | RCX=7 | 947656708 | 947656708 | 947656708 | yes | limit=8: deep recurrence |
| 4 | RCX=255 | 947656708 | 947656708 | 947656708 | yes | 0xFF: limit=8 |
| 5 | RCX=51966 | 30569571 | 30569571 | 30569571 | yes | 0xCAFE: limit=7 |
| 6 | RCX=74565 | 986115 | 986115 | 986115 | yes | 0x12345: limit=6 |
| 7 | RCX=57005 | 986115 | 986115 | 986115 | yes | 0xDEAD: limit=6 |
| 8 | RCX=128 | 0 | 0 | 0 | yes | 0x80: limit=1 |
| 9 | RCX=6 | 30569571 | 30569571 | 30569571 | yes | limit=7 |
| 10 | RCX=100 | 31810 | 31810 | 31810 | yes | 0x64: limit=5 |

## Source

```c
/* PC-state VM whose loop body uses 64-bit arithmetic.
 * Lift target: vm_int64_loop_target.
 * Goal: cover a multiplicative recurrence over int64 (acc = acc * 31 + i)
 * inside a VM dispatcher with the result truncated to int.  Tests the
 * lifter's handling of 64-bit mul/add inside loop bodies.
 */
#include <stdio.h>

enum I6VmPc {
    I6_LOAD       = 0,
    I6_INIT       = 1,
    I6_CHECK      = 2,
    I6_BODY_MUL   = 3,
    I6_BODY_ADD   = 4,
    I6_BODY_INC   = 5,
    I6_HALT       = 6,
};

__declspec(noinline)
int vm_int64_loop_target(int x) {
    long long acc = 0;
    int limit = 0;
    int idx   = 0;
    int pc    = I6_LOAD;

    while (1) {
        if (pc == I6_LOAD) {
            limit = (x & 7) + 1;
            acc = 0;
            pc = I6_INIT;
        } else if (pc == I6_INIT) {
            idx = 0;
            pc = I6_CHECK;
        } else if (pc == I6_CHECK) {
            pc = (idx < limit) ? I6_BODY_MUL : I6_HALT;
        } else if (pc == I6_BODY_MUL) {
            acc = acc * 31LL;
            pc = I6_BODY_ADD;
        } else if (pc == I6_BODY_ADD) {
            acc = acc + (long long)idx;
            pc = I6_BODY_INC;
        } else if (pc == I6_BODY_INC) {
            idx = idx + 1;
            pc = I6_CHECK;
        } else if (pc == I6_HALT) {
            return (int)(acc & 0xFFFFFFFFLL);
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_int64_loop(0xCAFE)=%d vm_int64_loop(0x12345)=%d\n",
           vm_int64_loop_target(0xCAFE),
           vm_int64_loop_target(0x12345));
    return 0;
}
```
