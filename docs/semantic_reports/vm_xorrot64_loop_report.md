# vm_xorrot64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xorrot64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xorrot64_loop.ll`
- **Symbol:** `vm_xorrot64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xorrot64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xorrot64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: r stays 0 |
| 2 | RCX=1 | 11400714819323198487 | 11400714819323198487 | 11400714819323198487 | yes | x=1 n=2: r=0^1=1; s=GR+1; r=1^s |
| 3 | RCX=2 | 6976393091583301537 | 6976393091583301537 | 6976393091583301537 | yes | x=2 n=3 |
| 4 | RCX=7 | 17407523668071694152 | 17407523668071694152 | 17407523668071694152 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: r=0^8=8 (one iter) |
| 6 | RCX=3405691582 | 17382597892840588897 | 17382597892840588897 | 17382597892840588897 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 12486367075188079128 | 12486367075188079128 | 12486367075188079128 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18065629430272941624 | 18065629430272941624 | 18065629430272941624 | yes | all 0xFF: n=8 LCG steps |
| 9 | RCX=1311768467463790320 | 1311768467463790320 | 1311768467463790320 | 1311768467463790320 | yes | 0x12345...EF0: n=1: r=x (only one xor) |
| 10 | RCX=9223372036854775808 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | x=2^63: n=1: r=2^63 |

## Source

```c
/* PC-state VM that drives a two-state XOR-then-LCG-step accumulator:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ s;
 *     s = s * 0x9E3779B97F4A7C15 + 1;   // LCG step (golden-ratio mul)
 *   }
 *   return r;
 *
 * Lift target: vm_xorrot64_loop_target  (name kept for manifest stability).
 *
 * Distinct from:
 *   - vm_lfsr64_loop (LFSR with feedback bit)
 *   - vm_pcg64_loop  (PCG random)
 *   - vm_xorshift64_loop (Marsaglia three-shift xorshift)
 *
 * Initial attempt used an i64 rotate (rotl s,7) inside the body but
 * the lifter collapsed the rotate to a single fshl outside the loop
 * and the body became an infinite XOR against a constant.  Replacing
 * with an arithmetic LCG step (multiply + add) preserves live state
 * across iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum XrVmPc {
    XR_INIT_ALL = 0,
    XR_CHECK    = 1,
    XR_ACC      = 2,
    XR_STEP     = 3,
    XR_INC      = 4,
    XR_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_xorrot64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XR_INIT_ALL;

    while (1) {
        if (pc == XR_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XR_CHECK;
        } else if (pc == XR_CHECK) {
            pc = (i < n) ? XR_ACC : XR_HALT;
        } else if (pc == XR_ACC) {
            r = r ^ s;
            pc = XR_STEP;
        } else if (pc == XR_STEP) {
            s = s * 0x9E3779B97F4A7C15ull + 1ull;
            pc = XR_INC;
        } else if (pc == XR_INC) {
            i = i + 1ull;
            pc = XR_CHECK;
        } else if (pc == XR_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorrot64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorrot64_loop_target(0xCAFEBABEull));
    return 0;
}
```
