# vm_signedxor_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signedxor_byte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_signedxor_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signedxor_byte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_signedxor_byte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signedxor_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: byte0=+1*1 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3: byte0=+2*1 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: byte0=+8*1 |
| 6 | RCX=3405691582 | 24 | 24 | — | **no** | 0xCAFEBABE: n=7 - high bits cancel pairwise |
| 7 | RCX=3735928559 | 236 | 236 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF: 8 sext(-1)*counters - high-bit fold cancels |
| 9 | RCX=9259542125412876287 | 0 | 0 | — | **no** | 0x80808080FFFFFFFF: 8 mixed signed bytes XOR cancel |
| 10 | RCX=1311768467463790320 | 18446744073709551600 | 18446744073709551600 | — | **no** | 0x12345...EF0: n=1 sext(0xF0)*1=-16 -> 2^64-16 (DIFFERENT from unsigned 240) |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: byte0=+1*1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: byte0=+2*1

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 contributes

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: byte0=+8*1

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 - high bits cancel pairwise

- inputs: `RCX=3405691582`
- manifest expected: `24`
- native: `24`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `236`
- native: `236`
- lifted: `—`

### case 8: all 0xFF: 8 sext(-1)*counters - high-bit fold cancels

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 9: 0x80808080FFFFFFFF: 8 mixed signed bytes XOR cancel

- inputs: `RCX=9259542125412876287`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 sext(0xF0)*1=-16 -> 2^64-16 (DIFFERENT from unsigned 240)

- inputs: `RCX=1311768467463790320`
- manifest expected: `18446744073709551600`
- native: `18446744073709551600`
- lifted: `—`

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
