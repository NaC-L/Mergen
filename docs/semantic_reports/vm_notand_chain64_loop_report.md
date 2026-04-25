# vm_notand_chain64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_notand_chain64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_notand_chain64_loop.ll`
- **Symbol:** `vm_notand_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_notand_chain64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_notand_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 (NOT AND 0 = 0; xor i<<3 keeps in low bits but r=0&0) |
| 2 | RCX=1 | 9 | 9 | 9 | yes | x=1 n=2: trace through 2 iters |
| 3 | RCX=2 | 16 | 16 | 16 | yes | x=2 n=3 |
| 4 | RCX=7 | 63 | 63 | 63 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 0 | 0 | 0 | yes | x=8 n=1: (~8)&8=0; xor 0=0 |
| 6 | RCX=3405691582 | 56 | 56 | 56 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3735928575 | 3735928575 | 3735928575 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | all 0xFF: ~r is single-bit, AND with all-1 keeps it; eight xor i<<3 over [0..56] flips 8 bytes |
| 9 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 single iter (~x)&x=0 |

## Source

```c
/* PC-state VM running a NOT-AND chain with dynamic-shift xor:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (~r) & x;
 *     r = r ^ (i << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_notand_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_subxor_chain64_loop    (sub + shl + xor)
 *   - vm_negstep64_loop         (negate + add)
 *
 * Tests bitwise NOT (`xor i64 r, -1`) followed by AND with input,
 * then xor with `i << 3` where i is the loop-index phi.  Combines
 * the bitwise NOT/AND idiom (also known as `andn`) with a dynamic
 * left-shift xor.
 */
#include <stdio.h>
#include <stdint.h>

enum NaVmPc {
    NA_INIT_ALL = 0,
    NA_CHECK    = 1,
    NA_BODY     = 2,
    NA_INC      = 3,
    NA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_notand_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NA_INIT_ALL;

    while (1) {
        if (pc == NA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = NA_CHECK;
        } else if (pc == NA_CHECK) {
            pc = (i < n) ? NA_BODY : NA_HALT;
        } else if (pc == NA_BODY) {
            r = (~r) & x;
            r = r ^ (i << 3);
            pc = NA_INC;
        } else if (pc == NA_INC) {
            i = i + 1ull;
            pc = NA_CHECK;
        } else if (pc == NA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_notand_chain64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_notand_chain64_loop_target(0xDEADBEEFull));
    return 0;
}
```
