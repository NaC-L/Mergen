# vm_xormuladd_chain64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xormuladd_chain64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xormuladd_chain64_loop.ll`
- **Symbol:** `vm_xormuladd_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xormuladd_chain64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xormuladd_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 (xor 0 mul add 0) |
| 2 | RCX=1 | 281488532864400 | 281488532864400 | 281488532864400 | yes | x=1 n=2 |
| 3 | RCX=2 | 681748796506855048 | 681748796506855048 | 681748796506855048 | yes | x=2 n=3 |
| 4 | RCX=7 | 11231052253945096160 | 11231052253945096160 | 11231052253945096160 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 134220960 | 134220960 | 134220960 | yes | x=8 n=1: 0^8 *prime + 8 |
| 6 | RCX=3405691582 | 18442958932354968712 | 18442958932354968712 | 18442958932354968712 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 1005864230212852640 | 1005864230212852640 | 1005864230212852640 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 9337678461245939488 | 9337678461245939488 | 9337678461245939488 | yes | all 0xFF: n=8 |
| 9 | RCX=72623859790382856 | 11182939659909142688 | 11182939659909142688 | 11182939659909142688 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 3689348814454379200 | 3689348814454379200 | 3689348814454379200 | yes | 0x12345...EF0: n=1 single iter |

## Source

```c
/* PC-state VM running a three-op single-state chain over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ x;
 *     r = r * 0x1000193ull;     // 24-bit FNV-32 prime
 *     r = r + x;
 *   }
 *   return r;
 *
 * Lift target: vm_xormuladd_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_murmurstep64_loop  (xor-mul-lshr fold; 64-bit magic)
 *   - vm_fmix_chain64_loop  (xor-mul-xor-mul; two 64-bit magics; no add)
 *   - vm_xxhmix64_loop      (xor-byte mul; post-loop fold)
 *   - vm_horner64_loop      (poly evaluation)
 *
 * Three sequential ops on a single i64 accumulator: xor with input,
 * multiply by 24-bit prime, add input.  No lshr fold; the multiply
 * uses a small-magic constant unlike the 64-bit Murmur/xxhash magics.
 */
#include <stdio.h>
#include <stdint.h>

enum XmVmPc {
    XM_INIT_ALL = 0,
    XM_CHECK    = 1,
    XM_BODY     = 2,
    XM_INC      = 3,
    XM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormuladd_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XM_INIT_ALL;

    while (1) {
        if (pc == XM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = XM_CHECK;
        } else if (pc == XM_CHECK) {
            pc = (i < n) ? XM_BODY : XM_HALT;
        } else if (pc == XM_BODY) {
            r = r ^ x;
            r = r * 0x1000193ull;
            r = r + x;
            pc = XM_INC;
        } else if (pc == XM_INC) {
            i = i + 1ull;
            pc = XM_CHECK;
        } else if (pc == XM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormuladd_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormuladd_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
```
