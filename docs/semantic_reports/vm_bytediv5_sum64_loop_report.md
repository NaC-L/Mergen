# vm_bytediv5_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytediv5_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bytediv5_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytediv5_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bytediv5_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytediv5_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 0 | 0 | — | **no** | x=1 n=2: 1/5=0 |
| 3 | RCX=2 | 0 | 0 | — | **no** | x=2 n=3: 2/5=0 |
| 4 | RCX=7 | 1 | 1 | — | **no** | x=7 n=8: byte0=7 -> 7/5=1 |
| 5 | RCX=8 | 1 | 1 | — | **no** | x=8 n=1: 8/5=1 |
| 6 | RCX=3405691582 | 165 | 165 | — | **no** | 0xCAFEBABE: n=7 sum of byte/5 |
| 7 | RCX=3735928559 | 163 | 163 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 408 | 408 | — | **no** | all 0xFF n=8: 8 * 51 = 408 |
| 9 | RCX=72623859790382856 | 1 | 1 | — | **no** | 0x0102...0708: n=1 byte0=8 -> 1 |
| 10 | RCX=1311768467463790320 | 48 | 48 | — | **no** | 0x12345...EF0: n=1 byte0=240 -> 240/5=48 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1/5=0

- inputs: `RCX=1`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 3: x=2 n=3: 2/5=0

- inputs: `RCX=2`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 4: x=7 n=8: byte0=7 -> 7/5=1

- inputs: `RCX=7`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 5: x=8 n=1: 8/5=1

- inputs: `RCX=8`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum of byte/5

- inputs: `RCX=3405691582`
- manifest expected: `165`
- native: `165`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `163`
- native: `163`
- lifted: `—`

### case 8: all 0xFF n=8: 8 * 51 = 408

- inputs: `RCX=18446744073709551615`
- manifest expected: `408`
- native: `408`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 -> 1

- inputs: `RCX=72623859790382856`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=240 -> 240/5=48

- inputs: `RCX=1311768467463790320`
- manifest expected: `48`
- native: `48`
- lifted: `—`

## Source

```c
/* PC-state VM that sums byte / 5 over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) / 5);   // udiv by 5
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytediv5_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_adler32_64_loop          (urem by 65521 - prime modular)
 *   - vm_trailzeros_factorial64_loop (udiv by 5 on a single state, log_5)
 *   - vm_uintadd_byte_idx64_loop  (byte * counter - mul not div)
 *
 * Tests `udiv i64 byte, 5` per iteration on a byte stream.  Compiler
 * may lower /5 to magic-number multiply but the lifter typically
 * preserves it as raw udiv (per documented Adler urem behavior).
 * All-0xFF accumulates 8 * (255/5) = 8 * 51 = 408.
 */
#include <stdio.h>
#include <stdint.h>

enum BdVmPc {
    BD_INIT_ALL = 0,
    BD_CHECK    = 1,
    BD_BODY     = 2,
    BD_INC      = 3,
    BD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytediv5_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BD_INIT_ALL;

    while (1) {
        if (pc == BD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BD_CHECK;
        } else if (pc == BD_CHECK) {
            pc = (i < n) ? BD_BODY : BD_HALT;
        } else if (pc == BD_BODY) {
            r = r + ((s & 0xFFull) / 5ull);
            s = s >> 8;
            pc = BD_INC;
        } else if (pc == BD_INC) {
            i = i + 1ull;
            pc = BD_CHECK;
        } else if (pc == BD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytediv5_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bytediv5_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
