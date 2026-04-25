# vm_mixed_intrinsics_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_mixed_intrinsics_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_mixed_intrinsics_loop.ll`
- **Symbol:** `vm_mixed_intrinsics_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_mixed_intrinsics_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_mixed_intrinsics_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, x=0 |
| 2 | RCX=1 | 922746885 | 922746885 | 922746885 | yes | limit=2 |
| 3 | RCX=7 | 67305502 | 67305502 | 67305502 | yes | limit=8 |
| 4 | RCX=255 | 4093837352 | 4093837352 | 4093837352 | yes | 0xFF: limit=8 |
| 5 | RCX=51966 | 2055733308 | 2055733308 | 2055733308 | yes | 0xCAFE: limit=7 |
| 6 | RCX=43981 | 3305177143 | 3305177143 | 3305177143 | yes | 0xABCD: limit=6 |
| 7 | RCX=74565 | 2983265837 | 2983265837 | 2983265837 | yes | 0x12345: limit=6 |
| 8 | RCX=-1 | 4227662042 | 4227662042 | 4227662042 | yes | all F |
| 9 | RCX=-559038737 | 3656937374 | 3656937374 | 3656937374 | yes | 0xDEADBEEF |
| 10 | RCX=128 | 2147483649 | 2147483649 | 2147483649 | yes | 0x80: limit=1 |
| 11 | RCX=16 | 268435457 | 268435457 | 268435457 | yes | 0x10: limit=1 |

## Source

```c
/* PC-state VM whose body chains TWO distinct intrinsic calls per iteration:
 *   sum += __builtin_popcount(v) + __builtin_bswap32(v)
 * Lift target: vm_mixed_intrinsics_loop_target.
 * Goal: probe whether the documented chain-of-two-calls correctness bug
 * (originally seen in vm_chain_imports_loop with two abs() calls) is
 * specific to abs or generalises to any pair of intrinsics.
 */
#include <stdio.h>

enum MiVmPc {
    MI_LOAD       = 0,
    MI_INIT       = 1,
    MI_CHECK      = 2,
    MI_BODY_VAL   = 3,
    MI_BODY_POPCNT= 4,
    MI_BODY_BSWAP = 5,
    MI_BODY_FOLD  = 6,
    MI_BODY_INC   = 7,
    MI_HALT       = 8,
};

__declspec(noinline)
int vm_mixed_intrinsics_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned pc_r  = 0;
    unsigned bs    = 0;
    int pc         = MI_LOAD;

    while (1) {
        if (pc == MI_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = MI_INIT;
        } else if (pc == MI_INIT) {
            idx = 0;
            pc = MI_CHECK;
        } else if (pc == MI_CHECK) {
            pc = (idx < limit) ? MI_BODY_VAL : MI_HALT;
        } else if (pc == MI_BODY_VAL) {
            v = (unsigned)x ^ (idx * 0x37);
            pc = MI_BODY_POPCNT;
        } else if (pc == MI_BODY_POPCNT) {
            pc_r = (unsigned)__builtin_popcount(v);
            pc = MI_BODY_BSWAP;
        } else if (pc == MI_BODY_BSWAP) {
            bs = __builtin_bswap32(v);
            pc = MI_BODY_FOLD;
        } else if (pc == MI_BODY_FOLD) {
            sum = sum + pc_r + bs;
            pc = MI_BODY_INC;
        } else if (pc == MI_BODY_INC) {
            idx = idx + 1;
            pc = MI_CHECK;
        } else if (pc == MI_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_mixed_intrinsics_loop(0xCAFE)=%u vm_mixed_intrinsics_loop(0xDEADBEEF)=%u\n",
           (unsigned)vm_mixed_intrinsics_loop_target(0xCAFE),
           (unsigned)vm_mixed_intrinsics_loop_target((int)0xDEADBEEFu));
    return 0;
}
```
