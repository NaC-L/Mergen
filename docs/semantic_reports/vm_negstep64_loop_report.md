# vm_negstep64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_negstep64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_negstep64_loop.ll`
- **Symbol:** `vm_negstep64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_negstep64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_negstep64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 n=1: r=-0+0=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: r=0+1=1; r=-1+2=1 |
| 3 | RCX=2 | 3 | 3 | 3 | yes | x=2 n=3 |
| 4 | RCX=7 | 4 | 4 | 4 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: r=0+8=8 |
| 6 | RCX=3405691582 | 3405691585 | 3405691585 | 3405691585 | yes | 0xCAFEBABE: n=7 odd trip leaves r near s+offset |
| 7 | RCX=3735928559 | 4 | 4 | 4 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 4 | 4 | 4 | yes | all 0xFF n=8: telescoping cancels to small constant |
| 9 | RCX=72623859790382856 | 72623859790382856 | 72623859790382856 | 72623859790382856 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 1311768467463790320 | 1311768467463790320 | 1311768467463790320 | yes | 0x12345...EF0: n=1 single iter |

## Source

```c
/* PC-state VM running a two-state recurrence with arithmetic negation:
 *
 *   n = (x & 7) + 1;
 *   r = 0; s = x;
 *   for (i = 0; i < n; i++) {
 *     r = -r + s;        // negate accumulator, add stepped state
 *     s = s + 1;
 *   }
 *   return r;
 *
 * Lift target: vm_negstep64_loop_target.
 *
 * Distinct from:
 *   - vm_subxor_chain64_loop (`(r-x)^(x<<3)` - sub of state minus input)
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_geosum64_loop / vm_squareadd64_loop (single-state arith)
 *
 * Tests the `sub i64 0, r` (negate) pattern inside a counter-bound
 * loop body chained with add and a stepped state.  The negation flips
 * sign of the accumulator each iter; with even trip count the sign
 * cancels out for many inputs.
 */
#include <stdio.h>
#include <stdint.h>

enum NgVmPc {
    NG_INIT_ALL = 0,
    NG_CHECK    = 1,
    NG_BODY     = 2,
    NG_INC      = 3,
    NG_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_negstep64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t s  = 0;
    uint64_t i  = 0;
    int      pc = NG_INIT_ALL;

    while (1) {
        if (pc == NG_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            s = x;
            i = 0ull;
            pc = NG_CHECK;
        } else if (pc == NG_CHECK) {
            pc = (i < n) ? NG_BODY : NG_HALT;
        } else if (pc == NG_BODY) {
            uint64_t nr = (uint64_t)(-(int64_t)r);
            r = nr + s;
            s = s + 1ull;
            pc = NG_INC;
        } else if (pc == NG_INC) {
            i = i + 1ull;
            pc = NG_CHECK;
        } else if (pc == NG_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_negstep64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_negstep64_loop_target(0xCAFEBABEull));
    return 0;
}
```
