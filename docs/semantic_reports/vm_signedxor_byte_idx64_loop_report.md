# vm_signedxor_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signedxor_byte_idx64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signedxor_byte_idx64_loop.ll`
- **Symbol:** `vm_signedxor_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signedxor_byte_idx64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signedxor_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: byte0=+1*1 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3: byte0=+2*1 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: byte0=+8*1 |
| 6 | RCX=3405691582 | 24 | 24 | 24 | yes | 0xCAFEBABE: n=7 - high bits cancel pairwise |
| 7 | RCX=3735928559 | 236 | 236 | 236 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: 8 sext(-1)*counters - high-bit fold cancels |
| 9 | RCX=9259542125412876287 | 0 | 0 | 0 | yes | 0x80808080FFFFFFFF: 8 mixed signed bytes XOR cancel |
| 10 | RCX=1311768467463790320 | 18446744073709551600 | 18446744073709551600 | 18446744073709551600 | yes | 0x12345...EF0: n=1 sext(0xF0)*1=-16 -> 2^64-16 (DIFFERENT from unsigned 240) |

## Source

```c
/* PC-state VM that XOR-folds SIGNED bytes scaled by counter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     r = r ^ (uint64_t)((int64_t)sb * (int64_t)(i + 1));
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_signedxor_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (UNSIGNED zext byte * counter, XOR-folded)
 *   - vm_bytesmul_idx64_loop     (signed sext byte * counter, ADD-folded)
 *
 * Fills the sext+XOR cell of the per-byte * counter matrix.  For
 * positive bytes (high bit clear) sext == zext so XOR is identical to
 * the unsigned variant; for negative bytes (>= 0x80) the sign-extended
 * value populates the upper 56 bits with 1s, producing a different
 * fold pattern than the zext version.
 */
#include <stdio.h>
#include <stdint.h>

enum SbVmPc {
    SB_INIT_ALL = 0,
    SB_CHECK    = 1,
    SB_BODY     = 2,
    SB_INC      = 3,
    SB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signedxor_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SB_INIT_ALL;

    while (1) {
        if (pc == SB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SB_CHECK;
        } else if (pc == SB_CHECK) {
            pc = (i < n) ? SB_BODY : SB_HALT;
        } else if (pc == SB_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r ^ (uint64_t)((int64_t)sb * (int64_t)(i + 1ull));
            s = s >> 8;
            pc = SB_INC;
        } else if (pc == SB_INC) {
            i = i + 1ull;
            pc = SB_CHECK;
        } else if (pc == SB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedxor_byte_idx64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_signedxor_byte_idx64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
```
