# vm_reverse_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_reverse_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_reverse_array_loop.ll`
- **Symbol:** `vm_reverse_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_reverse_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_reverse_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 7 | 7 | 7 | yes | seed=0: buf=[0..7] -> rev=[7..0] -> 7\|(0<<4) |
| 2 | RCX=1 | 24 | 24 | 24 | yes | seed=1 |
| 3 | RCX=5 | 92 | 92 | 92 | yes | seed=5 |
| 4 | RCX=7 | 126 | 126 | 126 | yes | seed=7 |
| 5 | RCX=8 | 143 | 143 | 143 | yes | seed=8 |
| 6 | RCX=18 | 41 | 41 | 41 | yes | 0x12: seed=2 |
| 7 | RCX=171 | 178 | 178 | 178 | yes | 0xAB: seed=11 |
| 8 | RCX=255 | 246 | 246 | 246 | yes | 0xFF: seed=15 |
| 9 | RCX=256 | 7 | 7 | 7 | yes | 0x100: seed=0 (mask) |
| 10 | RCX=51966 | 229 | 229 | 229 | yes | 0xCAFE: seed=14 |

## Source

```c
/* PC-state VM that copies a stack array into a second stack array in
 * REVERSED index order, then returns the first and last elements packed.
 * Lift target: vm_reverse_array_loop_target.
 * Goal: cover an indexed-load-with-derived-index pattern (buf[7-i]) inside
 * a VM dispatcher.  Avoids the in-place swap that trips BB-budget-503.
 */
#include <stdio.h>

enum RaVmPc {
    RA_LOAD       = 0,
    RA_INIT_FILL  = 1,
    RA_FILL_CHECK = 2,
    RA_FILL_BODY  = 3,
    RA_FILL_INC   = 4,
    RA_INIT_REV   = 5,
    RA_REV_CHECK  = 6,
    RA_REV_BODY   = 7,
    RA_REV_INC    = 8,
    RA_PACK       = 9,
    RA_HALT       = 10,
};

__declspec(noinline)
int vm_reverse_array_loop_target(int x) {
    int buf[8];
    int buf2[8];
    int idx    = 0;
    int result = 0;
    int seed   = 0;
    int pc     = RA_LOAD;

    while (1) {
        if (pc == RA_LOAD) {
            seed = x & 0xF;
            pc = RA_INIT_FILL;
        } else if (pc == RA_INIT_FILL) {
            idx = 0;
            pc = RA_FILL_CHECK;
        } else if (pc == RA_FILL_CHECK) {
            pc = (idx < 8) ? RA_FILL_BODY : RA_INIT_REV;
        } else if (pc == RA_FILL_BODY) {
            buf[idx] = (idx + seed) & 0xF;
            pc = RA_FILL_INC;
        } else if (pc == RA_FILL_INC) {
            idx = idx + 1;
            pc = RA_FILL_CHECK;
        } else if (pc == RA_INIT_REV) {
            idx = 0;
            pc = RA_REV_CHECK;
        } else if (pc == RA_REV_CHECK) {
            pc = (idx < 8) ? RA_REV_BODY : RA_PACK;
        } else if (pc == RA_REV_BODY) {
            buf2[idx] = buf[7 - idx];
            pc = RA_REV_INC;
        } else if (pc == RA_REV_INC) {
            idx = idx + 1;
            pc = RA_REV_CHECK;
        } else if (pc == RA_PACK) {
            result = (buf2[0] & 0xF) | ((buf2[7] & 0xF) << 4);
            pc = RA_HALT;
        } else if (pc == RA_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_reverse_array_loop(0x5)=%d vm_reverse_array_loop(0xCAFE)=%d\n",
           vm_reverse_array_loop_target(0x5),
           vm_reverse_array_loop_target(0xCAFE));
    return 0;
}
```
