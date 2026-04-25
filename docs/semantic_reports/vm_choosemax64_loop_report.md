# vm_choosemax64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_choosemax64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_choosemax64_loop.ll`
- **Symbol:** `vm_choosemax64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_choosemax64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_choosemax64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1 |
| 2 | RCX=1 | 10 | 10 | 10 | yes | x=1, n=2 |
| 3 | RCX=2 | 59 | 59 | 59 | yes | x=2, n=3 |
| 4 | RCX=7 | 47563 | 47563 | 47563 | yes | x=7, n=8 |
| 5 | RCX=15 | 656462487 | 656462487 | 656462487 | yes | x=15, n=16 max |
| 6 | RCX=255 | 10987675527 | 10987675527 | 10987675527 | yes | x=0xFF, n=16 |
| 7 | RCX=51966 | 745658888381 | 745658888381 | 745658888381 | yes | x=0xCAFE, n=15 |
| 8 | RCX=3405691582 | 48867951784388093 | 48867951784388093 | 48867951784388093 | yes | x=0xCAFEBABE, n=15 |
| 9 | RCX=18446744073709551615 | 18446744073709551493 | 18446744073709551493 | 18446744073709551493 | yes | max u64, n=16: wraps and opt2 wins many iters |
| 10 | RCX=11400714819323198485 | 15755400384260043894 | 15755400384260043894 | 15755400384260043894 | yes | K (golden), n=6 |

## Source

```c
/* PC-state VM that picks the larger (unsigned) of two derived options
 * per iteration on full uint64_t state.
 *   s = x; n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     opt1 = s * 3 + i
 *     opt2 = s + i*i
 *     s = (opt1 > opt2) ? opt1 : opt2
 *   return s;
 * Lift target: vm_choosemax64_loop_target.
 *
 * Distinct from vm_smax64_loop (signed-max accumulator over derived
 * sequence) and vm_satadd64_loop (overflow-clamp): per-iteration choice
 * between two locally-computed options via icmp ugt + select.
 */
#include <stdio.h>
#include <stdint.h>

enum CmVmPc {
    CM_LOAD       = 0,
    CM_INIT       = 1,
    CM_LOOP_CHECK = 2,
    CM_LOOP_BODY  = 3,
    CM_LOOP_INC   = 4,
    CM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_choosemax64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t s   = 0;
    int      pc  = CM_LOAD;

    while (1) {
        if (pc == CM_LOAD) {
            s = x;
            n = (int)(x & 0xFull) + 1;
            pc = CM_INIT;
        } else if (pc == CM_INIT) {
            idx = 0;
            pc = CM_LOOP_CHECK;
        } else if (pc == CM_LOOP_CHECK) {
            pc = (idx < n) ? CM_LOOP_BODY : CM_HALT;
        } else if (pc == CM_LOOP_BODY) {
            uint64_t opt1 = s * 3ull + (uint64_t)idx;
            uint64_t opt2 = s + (uint64_t)(idx * idx);
            s = (opt1 > opt2) ? opt1 : opt2;
            pc = CM_LOOP_INC;
        } else if (pc == CM_LOOP_INC) {
            idx = idx + 1;
            pc = CM_LOOP_CHECK;
        } else if (pc == CM_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_choosemax64(0xCAFE)=%llu vm_choosemax64(0xFF)=%llu\n",
           (unsigned long long)vm_choosemax64_loop_target(0xCAFEull),
           (unsigned long long)vm_choosemax64_loop_target(0xFFull));
    return 0;
}
```
