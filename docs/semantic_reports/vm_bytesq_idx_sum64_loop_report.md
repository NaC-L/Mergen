# vm_bytesq_idx_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytesq_idx_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bytesq_idx_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytesq_idx_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bytesq_idx_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytesq_idx_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: 1*1*1=1 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3: 2*1=2 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 -> 7*1=7 |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: 8*1*1=8 |
| 6 | RCX=3405691582 | 6452 | 6452 | — | **no** | 0xCAFEBABE: n=7 sum of byte*counter^2 |
| 7 | RCX=3735928559 | 6108 | 6108 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 52020 | 52020 | — | **no** | all 0xFF n=8: 0xFF*204=52020 |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte0=240 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1*1*1=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: 2*1=2

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 -> 7*1=7

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: 8*1*1=8

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum of byte*counter^2

- inputs: `RCX=3405691582`
- manifest expected: `6452`
- native: `6452`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `6108`
- native: `6108`
- lifted: `—`

### case 8: all 0xFF n=8: 0xFF*204=52020

- inputs: `RCX=18446744073709551615`
- manifest expected: `52020`
- native: `52020`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=240

- inputs: `RCX=1311768467463790320`
- manifest expected: `240`
- native: `240`
- lifted: `—`

## Source

```c
/* PC-state VM that sums byte * (i+1) * (i+1) over n = (x & 7) + 1 iters:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t c = i + 1;
 *     r = r + (s & 0xFF) * c * c;
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytesq_idx_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop (byte * counter, ADD) - linear counter
 *   - vm_xormul_byte_idx64_loop  (byte * counter, XOR) - linear counter
 *   - vm_bytesq_sum64_loop       (byte * byte - self-multiply, no counter)
 *
 * Tests SQUARED counter expression `(i+1)*(i+1)` as multiplier - two
 * sequential muls in the body (counter*counter then byte*counter^2)
 * inside a counter-bound loop.  All-0xFF: 0xFF * (1+4+9+16+25+36+49+64)
 * = 0xFF * 204 = 52020.
 */
#include <stdio.h>
#include <stdint.h>

enum BqVmPc {
    BQ_INIT_ALL = 0,
    BQ_CHECK    = 1,
    BQ_BODY     = 2,
    BQ_INC      = 3,
    BQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytesq_idx_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BQ_INIT_ALL;

    while (1) {
        if (pc == BQ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_CHECK) {
            pc = (i < n) ? BQ_BODY : BQ_HALT;
        } else if (pc == BQ_BODY) {
            uint64_t c = i + 1ull;
            r = r + (s & 0xFFull) * c * c;
            s = s >> 8;
            pc = BQ_INC;
        } else if (pc == BQ_INC) {
            i = i + 1ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytesq_idx_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bytesq_idx_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
