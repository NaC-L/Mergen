# vm_subbyte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_subbyte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_subbyte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_subbyte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_subbyte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_subbyte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 18446744073709551615 | 18446744073709551615 | — | **no** | x=1 n=2: 0-1*1=2^64-1 |
| 3 | RCX=2 | 18446744073709551614 | 18446744073709551614 | — | **no** | x=2 n=3: -2 in u64 |
| 4 | RCX=7 | 18446744073709551609 | 18446744073709551609 | — | **no** | x=7 n=8: -7 |
| 5 | RCX=8 | 18446744073709551608 | 18446744073709551608 | — | **no** | x=8 n=1: -8 |
| 6 | RCX=3405691582 | 18446744073709549484 | 18446744073709549484 | — | **no** | 0xCAFEBABE: n=7 sum-of-products subtracted |
| 7 | RCX=3735928559 | 18446744073709549590 | 18446744073709549590 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709542436 | 18446744073709542436 | — | **no** | all 0xFF n=8: -0xFF*36 = -9180 -> 2^64-9180 |
| 9 | RCX=72623859790382856 | 18446744073709551608 | 18446744073709551608 | — | **no** | 0x0102...0708: n=1 -byte0 -> -8 |
| 10 | RCX=1311768467463790320 | 18446744073709551376 | 18446744073709551376 | — | **no** | 0x12345...EF0: n=1 -240 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 0-1*1=2^64-1

- inputs: `RCX=1`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 3: x=2 n=3: -2 in u64

- inputs: `RCX=2`
- manifest expected: `18446744073709551614`
- native: `18446744073709551614`
- lifted: `—`

### case 4: x=7 n=8: -7

- inputs: `RCX=7`
- manifest expected: `18446744073709551609`
- native: `18446744073709551609`
- lifted: `—`

### case 5: x=8 n=1: -8

- inputs: `RCX=8`
- manifest expected: `18446744073709551608`
- native: `18446744073709551608`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum-of-products subtracted

- inputs: `RCX=3405691582`
- manifest expected: `18446744073709549484`
- native: `18446744073709549484`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `18446744073709549590`
- native: `18446744073709549590`
- lifted: `—`

### case 8: all 0xFF n=8: -0xFF*36 = -9180 -> 2^64-9180

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709542436`
- native: `18446744073709542436`
- lifted: `—`

### case 9: 0x0102...0708: n=1 -byte0 -> -8

- inputs: `RCX=72623859790382856`
- manifest expected: `18446744073709551608`
- native: `18446744073709551608`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 -240

- inputs: `RCX=1311768467463790320`
- manifest expected: `18446744073709551376`
- native: `18446744073709551376`
- lifted: `—`

## Source

```c
/* PC-state VM that SUBTRACTs unsigned-byte * counter from the
 * accumulator over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r - (s & 0xFF) * (i + 1);   // u8 zext * counter, SUB-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_subbyte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop (same body, ADD-folded)
 *   - vm_xormul_byte_idx64_loop  (same body, XOR-folded)
 *   - vm_andsum_byte_idx64_loop  (byte AND counter, ADD)
 *   - vm_orsum_byte_idx64_loop   (byte OR counter, OR)
 *
 * Completes the binary-op fold matrix for byte * counter accumulator
 * with SUB.  Result wraps below zero into u64 so most non-zero inputs
 * land near 2^64 - small_number.
 */
#include <stdio.h>
#include <stdint.h>

enum SbiVmPc {
    SBI_INIT_ALL = 0,
    SBI_CHECK    = 1,
    SBI_BODY     = 2,
    SBI_INC      = 3,
    SBI_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subbyte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SBI_INIT_ALL;

    while (1) {
        if (pc == SBI_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SBI_CHECK;
        } else if (pc == SBI_CHECK) {
            pc = (i < n) ? SBI_BODY : SBI_HALT;
        } else if (pc == SBI_BODY) {
            r = r - (s & 0xFFull) * (i + 1ull);
            s = s >> 8;
            pc = SBI_INC;
        } else if (pc == SBI_INC) {
            i = i + 1ull;
            pc = SBI_CHECK;
        } else if (pc == SBI_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subbyte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_subbyte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
