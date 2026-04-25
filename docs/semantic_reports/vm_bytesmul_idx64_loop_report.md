# vm_bytesmul_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytesmul_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bytesmul_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytesmul_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bytesmul_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytesmul_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: byte0=+1 *1 + byte1=0 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3: byte0=+2 *1 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: byte0=+7 *1; rest zero |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: byte0=+8 *1 |
| 6 | RCX=3405691582 | 18446744073709551188 | 18446744073709551188 | — | **no** | 0xCAFEBABE: n=7 mixed-sign bytes scaled by index |
| 7 | RCX=3735928559 | 18446744073709551082 | 18446744073709551082 | — | **no** | 0xDEADBEEF: n=8 mostly negative bytes |
| 8 | RCX=18446744073709551615 | 18446744073709551580 | 18446744073709551580 | — | **no** | all 0xFF n=8: -1*(1+2+...+8)=-36 -> 2^64-36 |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=+8 *1 |
| 10 | RCX=9259542125412876287 | 18446744073709548278 | 18446744073709548278 | — | **no** | 0x80808080FFFFFFFF: n=8 negative-byte-heavy mixed |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: byte0=+1 *1 + byte1=0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: byte0=+2 *1

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: byte0=+7 *1; rest zero

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: byte0=+8 *1

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 mixed-sign bytes scaled by index

- inputs: `RCX=3405691582`
- manifest expected: `18446744073709551188`
- native: `18446744073709551188`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8 mostly negative bytes

- inputs: `RCX=3735928559`
- manifest expected: `18446744073709551082`
- native: `18446744073709551082`
- lifted: `—`

### case 8: all 0xFF n=8: -1*(1+2+...+8)=-36 -> 2^64-36

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551580`
- native: `18446744073709551580`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=+8 *1

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x80808080FFFFFFFF: n=8 negative-byte-heavy mixed

- inputs: `RCX=9259542125412876287`
- manifest expected: `18446744073709548278`
- native: `18446744073709548278`
- lifted: `—`

## Source

```c
/* PC-state VM that accumulates each signed byte of x times its
 * 1-based loop index over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     r += (int64_t)sb * (int64_t)(i + 1);
 *     s >>= 8;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_bytesmul_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop  (sext bytes, no index multiplier)
 *   - vm_altbytesum64_loop     (alternating fixed sign, no multiplier)
 *   - vm_squareadd64_loop      (single quadratic recurrence on whole x)
 *
 * Tests sext-i8 byte multiplied by i+1 (i is loop-index phi) chained
 * into a signed accumulator that round-trips through u64.  The
 * (i+1) factor exercises i64 multiply against a dynamic counter
 * value rather than a constant.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_INC      = 3,
    BS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytesmul_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (i < n) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r + (int64_t)sb * (int64_t)(i + 1ull);
            s = s >> 8;
            pc = BS_INC;
        } else if (pc == BS_INC) {
            i = i + 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytesmul_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_bytesmul_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
```
