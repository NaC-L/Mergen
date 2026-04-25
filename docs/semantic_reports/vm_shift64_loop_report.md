# vm_shift64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_shift64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_shift64_loop.ll`
- **Symbol:** `vm_shift64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_shift64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_shift64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, state=0 |
| 2 | RCX=1 | 202 | 202 | 202 | yes | limit=2 |
| 3 | RCX=7 | 1014 | 1014 | 1014 | yes | limit=8 |
| 4 | RCX=255 | 695 | 695 | 695 | yes | 0xFF: limit=8 |
| 5 | RCX=51966 | 899 | 899 | 899 | yes | 0xCAFE: limit=7 |
| 6 | RCX=74565 | 858 | 858 | 858 | yes | 0x12345: limit=6 |
| 7 | RCX=-559038737 | 1139 | 1139 | 1139 | yes | 0xDEADBEEF |
| 8 | RCX=128 | 192 | 192 | 192 | yes | 0x80: limit=1 |
| 9 | RCX=-889275714 | 692 | 692 | 692 | yes | 0xCAFEBABE |
| 10 | RCX=66 | 520 | 520 | 520 | yes | 0x42: limit=3 |

## Source

```c
/* PC-state VM with a true 64-bit recurrence: state = state * GOLDEN64 + ...
 * extracts the high byte each iteration into a 32-bit sum.
 * Lift target: vm_shift64_loop_target.
 * Goal: cover loop body that requires REAL 64-bit arithmetic - the
 * multiplier 0x9E3779B97F4A7C15 doesn't fit in 32 bits so the lifter has
 * to retain mul i64 + lshr i64 + trunc rather than narrowing to i32.
 */
#include <stdio.h>

enum S6VmPc {
    S6_LOAD       = 0,
    S6_INIT       = 1,
    S6_CHECK      = 2,
    S6_BODY_MUL   = 3,
    S6_BODY_ADD   = 4,
    S6_BODY_HI    = 5,
    S6_BODY_FOLD  = 6,
    S6_BODY_INC   = 7,
    S6_HALT       = 8,
};

__declspec(noinline)
int vm_shift64_loop_target(int x) {
    unsigned long long state = 0;
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int hi    = 0;
    int pc    = S6_LOAD;

    while (1) {
        if (pc == S6_LOAD) {
            limit = (x & 7) + 1;
            state = (unsigned long long)(unsigned)x
                  | ((unsigned long long)(unsigned)x << 32);
            sum = 0;
            pc = S6_INIT;
        } else if (pc == S6_INIT) {
            idx = 0;
            pc = S6_CHECK;
        } else if (pc == S6_CHECK) {
            pc = (idx < limit) ? S6_BODY_MUL : S6_HALT;
        } else if (pc == S6_BODY_MUL) {
            state = state * 0x9E3779B97F4A7C15ULL;
            pc = S6_BODY_ADD;
        } else if (pc == S6_BODY_ADD) {
            state = state + (unsigned long long)(idx * 13);
            pc = S6_BODY_HI;
        } else if (pc == S6_BODY_HI) {
            hi = (int)((state >> 56) & 0xFF);
            pc = S6_BODY_FOLD;
        } else if (pc == S6_BODY_FOLD) {
            sum = sum + hi;
            pc = S6_BODY_INC;
        } else if (pc == S6_BODY_INC) {
            idx = idx + 1;
            pc = S6_CHECK;
        } else if (pc == S6_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_shift64_loop(0xCAFE)=%d vm_shift64_loop(0xDEADBEEF)=%d\n",
           vm_shift64_loop_target(0xCAFE),
           vm_shift64_loop_target((int)0xDEADBEEFu));
    return 0;
}
```
