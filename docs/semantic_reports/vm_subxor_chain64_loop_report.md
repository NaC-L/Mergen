# vm_subxor_chain64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_subxor_chain64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_subxor_chain64_loop.ll`
- **Symbol:** `vm_subxor_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_subxor_chain64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_subxor_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 (sub 0 xor 0) |
| 2 | RCX=1 | 15 | 15 | 15 | yes | x=1 n=2: r=1; (1-1)^8=8; (8-1)^8=0xF |
| 3 | RCX=2 | 12 | 12 | 12 | yes | x=2 n=3 |
| 4 | RCX=7 | 15 | 15 | 15 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 64 | 64 | 64 | yes | x=8 n=1: r=(8-8)^64=64 |
| 6 | RCX=3405691582 | 18446744044315466236 | 18446744044315466236 | 18446744044315466236 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3803042551 | 3803042551 | 3803042551 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 7 | 7 | 7 | yes | all 0xFF: x<<3 has low bits clear, sub wraps |
| 9 | RCX=72623859790382856 | 580990878323062848 | 580990878323062848 | 580990878323062848 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 10494147739710322560 | 10494147739710322560 | 10494147739710322560 | yes | 0x12345...EF0: n=1 single iter |

## Source

```c
/* PC-state VM running a sub-xor chain on a single state over n iters:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r - x) ^ (x << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_subxor_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_xorbytes64_loop        (XOR-only over byte stream)
 *   - vm_horner64_loop          (mul + add polynomial)
 *
 * Tests `sub i64` inside a counter-bound loop body chained with shl-3
 * and xor.  Sub is underused vs add in the existing sample set; this
 * sample exercises i64 subtract on a state that gets re-derived from
 * itself minus the input each iteration.  Note: r starts seeded with
 * x so that the first iter's (r - x) lands at zero before the xor.
 */
#include <stdio.h>
#include <stdint.h>

enum SxVmPc {
    SX_INIT_ALL = 0,
    SX_CHECK    = 1,
    SX_BODY     = 2,
    SX_INC      = 3,
    SX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subxor_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SX_INIT_ALL;

    while (1) {
        if (pc == SX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = SX_CHECK;
        } else if (pc == SX_CHECK) {
            pc = (i < n) ? SX_BODY : SX_HALT;
        } else if (pc == SX_BODY) {
            r = (r - x) ^ (x << 3);
            pc = SX_INC;
        } else if (pc == SX_INC) {
            i = i + 1ull;
            pc = SX_CHECK;
        } else if (pc == SX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subxor_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_subxor_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
```
