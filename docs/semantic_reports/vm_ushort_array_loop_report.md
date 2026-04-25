# vm_ushort_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_ushort_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_ushort_array_loop.ll`
- **Symbol:** `vm_ushort_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_ushort_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_ushort_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 2800 | 2800 | 2800 | yes | seed=0 |
| 2 | RCX=1 | 2808 | 2808 | 2808 | yes | seed=1 |
| 3 | RCX=100 | 3600 | 3600 | 3600 | yes | seed=100 |
| 4 | RCX=1000 | 10800 | 10800 | 10800 | yes | seed=1000 |
| 5 | RCX=32768 | 264944 | 264944 | 264944 | yes | seed=0x8000: high bit |
| 6 | RCX=65000 | 391728 | 391728 | 391728 | yes | 0xFDE8: u16 wrap on i=6,7 |
| 7 | RCX=65535 | 68328 | 68328 | 68328 | yes | 0xFFFF: max seed |
| 8 | RCX=51966 | 418528 | 418528 | 418528 | yes | 0xCAFE |
| 9 | RCX=74565 | 75032 | 75032 | 75032 | yes | 0x12345: high bits ignored |
| 10 | RCX=4294901761 | 2808 | 2808 | 2808 | yes | 0xFFFF0001: only low 16 used |

## Source

```c
/* PC-state VM that fills an unsigned-short[8] stack array and accumulates
 * via zero-extending loads.
 * Lift target: vm_ushort_array_loop_target.
 * Goal: cover an unsigned-i16-element stack array (zext i16 -> i32 at use
 * sites), distinct from the signed `short[]` variant which exercises
 * sext i16.  Symbolic seed keeps the per-element add from being folded.
 */
#include <stdio.h>

enum UaVmPc {
    UA_LOAD       = 0,
    UA_INIT_FILL  = 1,
    UA_FILL_CHECK = 2,
    UA_FILL_BODY  = 3,
    UA_FILL_INC   = 4,
    UA_INIT_SUM   = 5,
    UA_SUM_CHECK  = 6,
    UA_SUM_BODY   = 7,
    UA_SUM_INC    = 8,
    UA_HALT       = 9,
};

__declspec(noinline)
unsigned int vm_ushort_array_loop_target(unsigned int x) {
    unsigned short buf[8];
    int idx           = 0;
    unsigned int sum  = 0;
    unsigned short seed = 0;
    int pc            = UA_LOAD;

    while (1) {
        if (pc == UA_LOAD) {
            seed = (unsigned short)(x & 0xFFFFu);
            pc = UA_INIT_FILL;
        } else if (pc == UA_INIT_FILL) {
            idx = 0;
            pc = UA_FILL_CHECK;
        } else if (pc == UA_FILL_CHECK) {
            pc = (idx < 8) ? UA_FILL_BODY : UA_INIT_SUM;
        } else if (pc == UA_FILL_BODY) {
            buf[idx] = (unsigned short)((unsigned int)seed + (unsigned int)idx * 100u);
            pc = UA_FILL_INC;
        } else if (pc == UA_FILL_INC) {
            idx = idx + 1;
            pc = UA_FILL_CHECK;
        } else if (pc == UA_INIT_SUM) {
            idx = 0;
            pc = UA_SUM_CHECK;
        } else if (pc == UA_SUM_CHECK) {
            pc = (idx < 8) ? UA_SUM_BODY : UA_HALT;
        } else if (pc == UA_SUM_BODY) {
            sum = sum + (unsigned int)buf[idx];
            pc = UA_SUM_INC;
        } else if (pc == UA_SUM_INC) {
            idx = idx + 1;
            pc = UA_SUM_CHECK;
        } else if (pc == UA_HALT) {
            return sum;
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_ushort_array_loop(0xFDE8)=%u vm_ushort_array_loop(0xCAFE)=%u\n",
           vm_ushort_array_loop_target(0xFDE8u),
           vm_ushort_array_loop_target(0xCAFEu));
    return 0;
}
```
