# vm_orxor_pair64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_orxor_pair64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_orxor_pair64_loop.ll`
- **Symbol:** `vm_orxor_pair64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_orxor_pair64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_orxor_pair64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 a=0 b=0 n=1: a\|b=0; b=0^0=0; ret 0 |
| 2 | RCX=1 | 7 | 7 | 7 | yes | x=1 n=2: trace through 2 iters |
| 3 | RCX=2 | 100 | 100 | 100 | yes | x=2 n=3 |
| 4 | RCX=7 | 7332103 | 7332103 | 7332103 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 16 | 16 | 16 | yes | x=8 n=1: a\|0=8; b=8^0=8; ret 16 |
| 6 | RCX=3405691582 | 437732809233088 | 437732809233088 | 437732809233088 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3937552892141111 | 3937552892141111 | 3937552892141111 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 720599 | 720599 | 720599 | yes | all 0xFF: a\|b stays ~0; b evolves via XOR-mul *7 |
| 9 | RCX=72623859790382856 | 145247719580765712 | 145247719580765712 | 145247719580765712 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 2623536934927580640 | 2623536934927580640 | 2623536934927580640 | yes | 0x12345...EF0: n=1 |

## Source

```c
/* PC-state VM that runs a two-state OR/XOR-mul cross-feed:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t t = a;
 *     a = a | b;
 *     b = t ^ (b * 7);
 *   }
 *   return a + b;
 *
 * Lift target: vm_orxor_pair64_loop_target.
 *
 * Distinct from:
 *   - vm_pairmix64_loop          (two-state with add+mul-by-GR cross-feed)
 *   - vm_threestate_xormul64_loop (three-state cross-feed with mul-by-GR)
 *   - vm_orsum_byte_idx64_loop   (single-state OR fold over bytes)
 *
 * Tests an explicit temp barrier (`t = a`) so the OR (`a |= b`) and
 * XOR-mul (`b = t ^ b*7`) updates both see the original a value
 * before either is overwritten.  Combines monotone OR fold on `a`
 * with non-monotone XOR-mul evolution on `b`, returning a+b.
 */
#include <stdio.h>
#include <stdint.h>

enum OxVmPc {
    OX_INIT_ALL = 0,
    OX_CHECK    = 1,
    OX_BODY     = 2,
    OX_INC      = 3,
    OX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orxor_pair64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = OX_INIT_ALL;

    while (1) {
        if (pc == OX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = 0ull;
            i = 0ull;
            pc = OX_CHECK;
        } else if (pc == OX_CHECK) {
            pc = (i < n) ? OX_BODY : OX_HALT;
        } else if (pc == OX_BODY) {
            uint64_t t = a;
            a = a | b;
            b = t ^ (b * 7ull);
            pc = OX_INC;
        } else if (pc == OX_INC) {
            i = i + 1ull;
            pc = OX_CHECK;
        } else if (pc == OX_HALT) {
            return a + b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orxor_pair64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_orxor_pair64_loop_target(0xCAFEBABEull));
    return 0;
}
```
