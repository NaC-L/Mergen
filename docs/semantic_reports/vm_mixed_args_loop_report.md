# vm_mixed_args_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_mixed_args_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_mixed_args_loop.ll`
- **Symbol:** `vm_mixed_args_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_mixed_args_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_mixed_args_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | x=0, y=0 |
| 2 | RCX=1, RDX=0 | 32 | 32 | 32 | yes | x=1, y=0, n=2: 1*31+1=32 |
| 3 | RCX=1, RDX=3405691582 | 104530782 | 104530782 | 104530782 | yes | x=1, y=0xCAFEBABE |
| 4 | RCX=7, RDX=18446744073709551615 | 3246867583 | 3246867583 | 3246867583 | yes | x=7, y=max u64, n=8 |
| 5 | RCX=255, RDX=1311768467463790320 | 1668062832 | 1668062832 | 1668062832 | yes | x=0xFF, y=0x123456789ABCDEF0, n=8 |
| 6 | RCX=65537, RDX=65537 | 65078241 | 65078241 | 65078241 | yes | x=y=0x10001, n=2 |
| 7 | RCX=4294967295, RDX=1 | 4122582657 | 4122582657 | 4122582657 | yes | x=-1 (sign-ext to -1 i64), n=8 |
| 8 | RCX=5, RDX=7 | 2065475751 | 2065475751 | 2065475751 | yes | x=5, y=7, n=6 |
| 9 | RCX=3, RDX=223195403574957 | 1839671533 | 1839671533 | 1839671533 | yes | x=3, y=0xCAFEBABEDEAD, n=4 |
| 10 | RCX=2147483648, RDX=9223372036854775808 | 2147483648 | 2147483648 | 2147483648 | yes | x=0x80000000 (sign-ext negative), y=2^63 |

## Source

```c
/* PC-state VM with MIXED-WIDTH input parameters: int x in RCX, full
 * uint64_t y in RDX.  Runs state = state*31 + (uint64_t)x for
 * n = (x & 7) + 1 iterations starting from state = y, then returns the
 * low 32 bits.
 * Lift target: vm_mixed_args_loop_target.
 *
 * Distinct from vm_two_input_loop (both i32) and vm_i64_return_loop
 * (single i64 in/out): here the lifter must consume RCX as a 32-bit value
 * (with sign extension to i64 for the additive term) and RDX as a full
 * 64-bit value live across the loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT       = 1,
    MA_LOOP_CHECK = 2,
    MA_LOOP_BODY  = 3,
    MA_LOOP_INC   = 4,
    MA_HALT       = 5,
};

__declspec(noinline)
unsigned int vm_mixed_args_loop_target(int x, uint64_t y) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int64_t  add   = 0;
    int      pc    = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            n     = (x & 7) + 1;
            state = y;
            add   = (int64_t)x;        /* sign-extend i32 -> i64 */
            pc = MA_INIT;
        } else if (pc == MA_INIT) {
            idx = 0;
            pc = MA_LOOP_CHECK;
        } else if (pc == MA_LOOP_CHECK) {
            pc = (idx < n) ? MA_LOOP_BODY : MA_HALT;
        } else if (pc == MA_LOOP_BODY) {
            state = state * 31ull + (uint64_t)add;
            pc = MA_LOOP_INC;
        } else if (pc == MA_LOOP_INC) {
            idx = idx + 1;
            pc = MA_LOOP_CHECK;
        } else if (pc == MA_HALT) {
            return (unsigned int)(state & 0xFFFFFFFFu);
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_mixed_args(1,0xCAFEBABE)=%u vm_mixed_args(0xFF,0x123456789ABCDEF0)=%u\n",
           vm_mixed_args_loop_target(1, 0xCAFEBABEull),
           vm_mixed_args_loop_target(0xFF, 0x123456789ABCDEF0ull));
    return 0;
}
```
