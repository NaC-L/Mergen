# vm_treepath64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_treepath64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_treepath64_loop.ll`
- **Symbol:** `vm_treepath64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_treepath64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_treepath64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1, bit0=0: s = 0*2 = 0 |
| 2 | RCX=1 | 2 | 2 | 2 | yes | x=1, n=2: bit0=1 then bit1=0 -> 1 then 2 |
| 3 | RCX=7 | 416 | 416 | 416 | yes | x=7, n=8: 3 set bits low |
| 4 | RCX=63 | 12682136550675316736 | 12682136550675316736 | 12682136550675316736 | yes | x=0x3F, n=64: 6 set bits low + 58 high zeros |
| 5 | RCX=64 | 0 | 0 | 0 | yes | x=0x40, n=1: bit0=0 |
| 6 | RCX=255 | 14987979559889010688 | 14987979559889010688 | 14987979559889010688 | yes | x=0xFF, n=64: 8 set bits low |
| 7 | RCX=51966 | 14927180964919508992 | 14927180964919508992 | 14927180964919508992 | yes | x=0xCAFE, n=63 |
| 8 | RCX=3405691582 | 17133061565256302592 | 17133061565256302592 | 17133061565256302592 | yes | x=0xCAFEBABE, n=63 |
| 9 | RCX=18446744073709551615 | 13589915092710809216 | 13589915092710809216 | 13589915092710809216 | yes | max u64, n=64: 3*x+1 every iter wraps mod 2^64 |
| 10 | RCX=11400714819323198485 | 96332860 | 96332860 | 96332860 | yes | K (golden), n=22 |

## Source

```c
/* PC-state VM that walks a binary-tree-shaped state recurrence driven
 * by the bits of x at each iteration index.
 *   s = 0; n = (x & 0x3F) + 1;
 *   for i in 0..n:
 *     bit = (x >> i) & 1
 *     if bit: s = s * 3 + 1
 *     else:   s = s * 2
 *   return s;
 * Returns full uint64_t.  Lift target: vm_treepath64_loop_target.
 *
 * Distinct from existing samples: the per-iteration BRANCH direction is
 * determined by reading a different bit of the input each time
 * (variable shift amount = loop counter).  Exercises i64 mul-by-2 vs
 * mul-by-3+1 conditional-update inside a variable-trip loop.
 */
#include <stdio.h>
#include <stdint.h>

enum TpVmPc {
    TP_LOAD       = 0,
    TP_INIT       = 1,
    TP_LOOP_CHECK = 2,
    TP_LOOP_BODY  = 3,
    TP_LOOP_INC   = 4,
    TP_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_treepath64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = TP_LOAD;

    while (1) {
        if (pc == TP_LOAD) {
            xx = x;
            n  = (int)(x & 0x3Full) + 1;
            s  = 0ull;
            pc = TP_INIT;
        } else if (pc == TP_INIT) {
            idx = 0;
            pc = TP_LOOP_CHECK;
        } else if (pc == TP_LOOP_CHECK) {
            pc = (idx < n) ? TP_LOOP_BODY : TP_HALT;
        } else if (pc == TP_LOOP_BODY) {
            uint64_t bit = (xx >> idx) & 1ull;
            if (bit) {
                s = s * 3ull + 1ull;
            } else {
                s = s * 2ull;
            }
            pc = TP_LOOP_INC;
        } else if (pc == TP_LOOP_INC) {
            idx = idx + 1;
            pc = TP_LOOP_CHECK;
        } else if (pc == TP_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_treepath64(0xCAFE)=%llu vm_treepath64(0xFF)=%llu\n",
           (unsigned long long)vm_treepath64_loop_target(0xCAFEull),
           (unsigned long long)vm_treepath64_loop_target(0xFFull));
    return 0;
}
```
