# vm_bytesq_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytesq_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bytesq_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytesq_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bytesq_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytesq_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: 1*1 + 0=1 |
| 3 | RCX=2 | 4 | 4 | — | **no** | x=2 n=3: 2*2=4 |
| 4 | RCX=7 | 49 | 49 | — | **no** | x=7 n=8: only byte0=7 -> 49 |
| 5 | RCX=8 | 64 | 64 | — | **no** | x=8 n=1: 8*8=64 |
| 6 | RCX=3405691582 | 176016 | 176016 | — | **no** | 0xCAFEBABE: n=7 sum of squared bytes |
| 7 | RCX=3735928559 | 172434 | 172434 | — | **no** | 0xDEADBEEF: n=8 sum of squared bytes |
| 8 | RCX=18446744073709551615 | 520200 | 520200 | — | **no** | all 0xFF n=8: 8*255*255=520200 |
| 9 | RCX=72623859790382856 | 64 | 64 | — | **no** | 0x0102...0708: n=1 byte0=8 -> 64 |
| 10 | RCX=1311768467463790320 | 57600 | 57600 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0=240 -> 57600 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1*1 + 0=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: 2*2=4

- inputs: `RCX=2`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 -> 49

- inputs: `RCX=7`
- manifest expected: `49`
- native: `49`
- lifted: `—`

### case 5: x=8 n=1: 8*8=64

- inputs: `RCX=8`
- manifest expected: `64`
- native: `64`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum of squared bytes

- inputs: `RCX=3405691582`
- manifest expected: `176016`
- native: `176016`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8 sum of squared bytes

- inputs: `RCX=3735928559`
- manifest expected: `172434`
- native: `172434`
- lifted: `—`

### case 8: all 0xFF n=8: 8*255*255=520200

- inputs: `RCX=18446744073709551615`
- manifest expected: `520200`
- native: `520200`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 -> 64

- inputs: `RCX=72623859790382856`
- manifest expected: `64`
- native: `64`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0=240 -> 57600

- inputs: `RCX=1311768467463790320`
- manifest expected: `57600`
- native: `57600`
- lifted: `—`

## Source

```c
/* PC-state VM that sums squared bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r + b * b;          // u8 squared
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytesq_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_popsq64_loop           (sum of squared POPCOUNTS of bytes)
 *   - vm_squareadd64_loop       (single-state r = r*r + i quadratic)
 *   - vm_uintadd_byte_idx64_loop (byte * counter)
 *
 * Tests u8 self-multiply (b * b) accumulator across a byte stream.
 * No counter scaling; every byte squared and summed.  All-0xFF input
 * accumulates 8 * 255*255 = 8 * 65025 = 520200.
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
uint64_t vm_bytesq_sum64_loop_target(uint64_t x) {
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
            uint64_t b = s & 0xFFull;
            r = r + b * b;
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
    printf("vm_bytesq_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_bytesq_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
