# vm_vartrip_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_vartrip_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_vartrip_array_loop.ll`
- **Symbol:** `vm_vartrip_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_vartrip_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_vartrip_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=1, seed_hi=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | n=2, seed_hi=0 |
| 3 | RCX=7 | 28 | 28 | 28 | yes | n=8, seed_hi=0: triangle |
| 4 | RCX=15 | 120 | 120 | 120 | yes | 0xF: n=16 max, seed_hi=0 |
| 5 | RCX=16 | 0 | 0 | 0 | yes | 0x10: n=1, seed_hi=0 |
| 6 | RCX=255 | 120 | 120 | 120 | yes | 0xFF: n=16, seed_hi=0 |
| 7 | RCX=256 | 1 | 1 | 1 | yes | 0x100: n=1, seed_hi=1 |
| 8 | RCX=4660 | 92 | 92 | 92 | yes | 0x1234: n=5, seed_hi=18 |
| 9 | RCX=51966 | 2995 | 2995 | 2995 | yes | 0xCAFE: n=15, seed_hi=0xCA |
| 10 | RCX=3405691582 | 199552195 | 199552195 | 199552195 | yes | 0xCAFEBABE: n=15, seed_hi=0xCAFEBA |

## Source

```c
/* PC-state VM with a 16-slot stack array and an INPUT-DERIVED trip
 * count (n = (x & 0xF) + 1, range 1..16).  Single fill+sum fused into
 * the loop body to keep the lifter's analysis budget within range while
 * still exercising a variable-trip stack-array loop.
 * Lift target: vm_vartrip_array_loop_target.
 *
 * Distinct from existing samples that fix the trip count to 8/16 and
 * unroll fully; here the lifter must keep a real loop body because the
 * trip count is not constant.
 */
#include <stdio.h>

enum VtVmPc {
    VT_LOAD       = 0,
    VT_INIT       = 1,
    VT_LOOP_CHECK = 2,
    VT_LOOP_BODY  = 3,
    VT_LOOP_INC   = 4,
    VT_HALT       = 5,
};

__declspec(noinline)
int vm_vartrip_array_loop_target(int x) {
    int buf[16];
    int idx     = 0;
    int sum     = 0;
    int n       = 0;
    int seed_hi = 0;
    int pc      = VT_LOAD;

    while (1) {
        if (pc == VT_LOAD) {
            n       = (x & 0xF) + 1;
            seed_hi = (int)((unsigned int)x >> 8);
            idx     = 0;
            sum     = 0;
            pc = VT_INIT;
        } else if (pc == VT_INIT) {
            idx = 0;
            pc = VT_LOOP_CHECK;
        } else if (pc == VT_LOOP_CHECK) {
            pc = (idx < n) ? VT_LOOP_BODY : VT_HALT;
        } else if (pc == VT_LOOP_BODY) {
            buf[idx] = idx ^ seed_hi;
            sum = sum + buf[idx];
            pc = VT_LOOP_INC;
        } else if (pc == VT_LOOP_INC) {
            idx = idx + 1;
            pc = VT_LOOP_CHECK;
        } else if (pc == VT_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_vartrip(0xF)=%d vm_vartrip(0xCAFE)=%d\n",
           vm_vartrip_array_loop_target(0xF),
           vm_vartrip_array_loop_target(0xCAFE));
    return 0;
}
```
