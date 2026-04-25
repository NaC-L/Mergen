# vm_bytemod3_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytemod3_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bytemod3_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytemod3_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bytemod3_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytemod3_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: 1%3=1 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3: 2%3=2 |
| 4 | RCX=7 | 1 | 1 | — | **no** | x=7 n=8: byte0=7 -> 7%3=1 |
| 5 | RCX=8 | 2 | 2 | — | **no** | x=8 n=1: 8%3=2 |
| 6 | RCX=3405691582 | 4 | 4 | — | **no** | 0xCAFEBABE: n=7 sum of byte%3 |
| 7 | RCX=3735928559 | 5 | 5 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF n=8: 255%3=0 (255=85*3) so 0 |
| 9 | RCX=72623859790382856 | 2 | 2 | — | **no** | 0x0102...0708: n=1 byte0=8 -> 2 |
| 10 | RCX=1311768467463790320 | 0 | 0 | — | **no** | 0x12345...EF0: n=1 byte0=240 -> 240%3=0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1%3=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: 2%3=2

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: byte0=7 -> 7%3=1

- inputs: `RCX=7`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 5: x=8 n=1: 8%3=2

- inputs: `RCX=8`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum of byte%3

- inputs: `RCX=3405691582`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `5`
- native: `5`
- lifted: `—`

### case 8: all 0xFF n=8: 255%3=0 (255=85*3) so 0

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 -> 2

- inputs: `RCX=72623859790382856`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=240 -> 240%3=0

- inputs: `RCX=1311768467463790320`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM that sums byte % 3 over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) % 3);   // urem by 3
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytemod3_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytediv5_sum64_loop  (per-byte udiv by 5)
 *   - vm_adler32_64_loop      (urem by 65521 prime)
 *
 * Tests `urem i64 byte, 3` per iteration on a byte stream with ADD
 * accumulator.  Small-modulus complement to /5 sample - exercises
 * urem-by-small-prime separately from the div-by-5 path.  All-0xFF
 * accumulates 8 * (255 % 3) = 8 * 0 = 0.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_INIT_ALL = 0,
    BM_CHECK    = 1,
    BM_BODY     = 2,
    BM_INC      = 3,
    BM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytemod3_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BM_INIT_ALL;

    while (1) {
        if (pc == BM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BM_CHECK;
        } else if (pc == BM_CHECK) {
            pc = (i < n) ? BM_BODY : BM_HALT;
        } else if (pc == BM_BODY) {
            r = r + ((s & 0xFFull) % 3ull);
            s = s >> 8;
            pc = BM_INC;
        } else if (pc == BM_INC) {
            i = i + 1ull;
            pc = BM_CHECK;
        } else if (pc == BM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytemod3_sum64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_bytemod3_sum64_loop_target(0xDEADBEEFull));
    return 0;
}
```
