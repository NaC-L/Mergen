# vm_signed_dword_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_dword_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_signed_dword_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_dword_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_signed_dword_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_dword_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: dword=1 +0 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=1: dword=2 |
| 4 | RCX=3 | 3 | 3 | — | **no** | x=3 n=2 |
| 5 | RCX=3405691582 | 18446744072820275902 | 18446744072820275902 | — | **no** | 0xCAFEBABE: n=1 dword high bit set, sext negative -> 2^64-magnitude |
| 6 | RCX=3735928559 | 18446744073150512879 | 18446744073150512879 | — | **no** | 0xDEADBEEF: n=2 negative + zero |
| 7 | RCX=18446744073709551615 | 18446744073709551614 | 18446744073709551614 | — | **no** | all 0xFF: 2 sext(-1) sums = -2 -> 2^64-2 |
| 8 | RCX=2147483648 | 18446744071562067968 | 18446744071562067968 | — | **no** | x=2^31 (most negative i32) n=1: -2^31 |
| 9 | RCX=9223372034707292160 | 18446744071562067968 | 18446744071562067968 | — | **no** | 0x7FFFFFFF80000000: n=1 lower=0x80000000=-2^31 |
| 10 | RCX=1311768467463790320 | 18446744072010653424 | 18446744072010653424 | — | **no** | 0x12345...EF0: n=1 lower dword high bit set |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: dword=1 +0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=1: dword=2

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=3 n=2

- inputs: `RCX=3`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 5: 0xCAFEBABE: n=1 dword high bit set, sext negative -> 2^64-magnitude

- inputs: `RCX=3405691582`
- manifest expected: `18446744072820275902`
- native: `18446744072820275902`
- lifted: `—`

### case 6: 0xDEADBEEF: n=2 negative + zero

- inputs: `RCX=3735928559`
- manifest expected: `18446744073150512879`
- native: `18446744073150512879`
- lifted: `—`

### case 7: all 0xFF: 2 sext(-1) sums = -2 -> 2^64-2

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551614`
- native: `18446744073709551614`
- lifted: `—`

### case 8: x=2^31 (most negative i32) n=1: -2^31

- inputs: `RCX=2147483648`
- manifest expected: `18446744071562067968`
- native: `18446744071562067968`
- lifted: `—`

### case 9: 0x7FFFFFFF80000000: n=1 lower=0x80000000=-2^31

- inputs: `RCX=9223372034707292160`
- manifest expected: `18446744071562067968`
- native: `18446744071562067968`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 lower dword high bit set

- inputs: `RCX=1311768467463790320`
- manifest expected: `18446744072010653424`
- native: `18446744072010653424`
- lifted: `—`

## Source

```c
/* PC-state VM that sums sext-i32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     r = r + (int64_t)sd;     // sext i32 -> i64
 *     s >>= 32;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signed_dword_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop  (sext-i8 byte sum, 8-bit stride)
 *   - vm_dword_xormul64_loop   (zext-i32 dword XOR, no sign extension)
 *
 * Tests `sext i32 to i64` per iteration on a 32-bit dword stream
 * (high bit of dword sign-extends).  Negative-dword inputs land
 * near 2^64 - magnitude in the sum.
 */
#include <stdio.h>
#include <stdint.h>

enum SdVmPc {
    SD_INIT_ALL = 0,
    SD_CHECK    = 1,
    SD_BODY     = 2,
    SD_INC      = 3,
    SD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signed_dword_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = SD_INIT_ALL;

    while (1) {
        if (pc == SD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = SD_CHECK;
        } else if (pc == SD_CHECK) {
            pc = (i < n) ? SD_BODY : SD_HALT;
        } else if (pc == SD_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            r = r + (int64_t)sd;
            s = s >> 32;
            pc = SD_INC;
        } else if (pc == SD_INC) {
            i = i + 1ull;
            pc = SD_CHECK;
        } else if (pc == SD_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_dword_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signed_dword_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
