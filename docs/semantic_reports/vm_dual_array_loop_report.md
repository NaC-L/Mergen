# vm_dual_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dual_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dual_array_loop.ll`
- **Symbol:** `vm_dual_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dual_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dual_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | seed=0: zero product |
| 2 | RCX=1 | 120 | 120 | 120 | yes | seed=1 |
| 3 | RCX=2 | 312 | 312 | 312 | yes | seed=2 |
| 4 | RCX=5 | 1320 | 1320 | 1320 | yes | seed=5 |
| 5 | RCX=10 | 4440 | 4440 | 4440 | yes | seed=10 |
| 6 | RCX=100 | 368400 | 368400 | 368400 | yes | seed=100 |
| 7 | RCX=1000 | 36084000 | 36084000 | 36084000 | yes | seed=1000 |
| 8 | RCX=65536 | 5505024 | 5505024 | 5505024 | yes | seed=0x10000: high-bit interaction |
| 9 | RCX=2147483647 | 4294967248 | 4294967248 | 4294967248 | yes | INT_MAX: 2-comp wrap |
| 10 | RCX=4294967295 | 4294967248 | 4294967248 | 4294967248 | yes | -1 u32: same as INT_MAX (mul wraps) |

## Source

```c
/* PC-state VM that allocates TWO independent int[8] stack arrays at the
 * same time, fills each with a different formula, and accumulates a
 * cross-product sum_{i}(a[i] * b[7-i]).
 * Lift target: vm_dual_array_loop_target.
 * Goal: cover two simultaneous stack arrays in flight (distinct stack
 * slots, independent fill loops, paired access in a third loop), as
 * opposed to existing samples that operate on a single stack array.
 */
#include <stdio.h>

enum DaVmPc {
    DA_LOAD       = 0,
    DA_INIT_FILL  = 1,
    DA_FILL_CHECK = 2,
    DA_FILL_BODY  = 3,
    DA_FILL_INC   = 4,
    DA_INIT_PROD  = 5,
    DA_PROD_CHECK = 6,
    DA_PROD_BODY  = 7,
    DA_PROD_INC   = 8,
    DA_HALT       = 9,
};

__declspec(noinline)
int vm_dual_array_loop_target(int x) {
    int a[8];
    int b[8];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = DA_LOAD;

    while (1) {
        if (pc == DA_LOAD) {
            seed = x;
            pc = DA_INIT_FILL;
        } else if (pc == DA_INIT_FILL) {
            idx = 0;
            pc = DA_FILL_CHECK;
        } else if (pc == DA_FILL_CHECK) {
            pc = (idx < 8) ? DA_FILL_BODY : DA_INIT_PROD;
        } else if (pc == DA_FILL_BODY) {
            a[idx] = seed + idx;
            b[idx] = seed * (idx + 1);
            pc = DA_FILL_INC;
        } else if (pc == DA_FILL_INC) {
            idx = idx + 1;
            pc = DA_FILL_CHECK;
        } else if (pc == DA_INIT_PROD) {
            idx = 0;
            pc = DA_PROD_CHECK;
        } else if (pc == DA_PROD_CHECK) {
            pc = (idx < 8) ? DA_PROD_BODY : DA_HALT;
        } else if (pc == DA_PROD_BODY) {
            sum = sum + a[idx] * b[7 - idx];
            pc = DA_PROD_INC;
        } else if (pc == DA_PROD_INC) {
            idx = idx + 1;
            pc = DA_PROD_CHECK;
        } else if (pc == DA_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dual_array_loop(10)=%d vm_dual_array_loop(100)=%d\n",
           vm_dual_array_loop_target(10),
           vm_dual_array_loop_target(100));
    return 0;
}
```
