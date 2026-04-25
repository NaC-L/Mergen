# vm_dynlshr_accum_byte64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dynlshr_accum_byte64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_dynlshr_accum_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dynlshr_accum_byte64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dynlshr_accum_byte64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dynlshr_accum_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 9223372036854775807 | 9223372036854775807 | — | **no** | x=0 n=1: r=~0 >> 1 ^ 0 = 2^63-1 |
| 2 | RCX=1 | 2305843009213693951 | 2305843009213693951 | — | **no** | x=1 n=2 |
| 3 | RCX=2 | 288230376151711743 | 288230376151711743 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 268435455 | 268435455 | — | **no** | x=7 n=8: cumulative right shift 36 bits |
| 5 | RCX=8 | 9223372036854775799 | 9223372036854775799 | — | **no** | x=8 n=1: ~0>>1 ^ 8 = (2^63-1) ^ 8 |
| 6 | RCX=3405691582 | 68719476735 | 68719476735 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 268435455 | 268435455 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 268435200 | 268435200 | — | **no** | all 0xFF n=8: cumulative shift collapses then XOR 0xFF stack |
| 9 | RCX=72623859790382856 | 9223372036854775799 | 9223372036854775799 | — | **no** | 0x0102...0708: n=1 byte0=8 (matches x=8) |
| 10 | RCX=1311768467463790320 | 9223372036854775567 | 9223372036854775567 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 |

## Failure detail

### case 1: x=0 n=1: r=~0 >> 1 ^ 0 = 2^63-1

- inputs: `RCX=0`
- manifest expected: `9223372036854775807`
- native: `9223372036854775807`
- lifted: `—`

### case 2: x=1 n=2

- inputs: `RCX=1`
- manifest expected: `2305843009213693951`
- native: `2305843009213693951`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `288230376151711743`
- native: `288230376151711743`
- lifted: `—`

### case 4: x=7 n=8: cumulative right shift 36 bits

- inputs: `RCX=7`
- manifest expected: `268435455`
- native: `268435455`
- lifted: `—`

### case 5: x=8 n=1: ~0>>1 ^ 8 = (2^63-1) ^ 8

- inputs: `RCX=8`
- manifest expected: `9223372036854775799`
- native: `9223372036854775799`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `68719476735`
- native: `68719476735`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `268435455`
- native: `268435455`
- lifted: `—`

### case 8: all 0xFF n=8: cumulative shift collapses then XOR 0xFF stack

- inputs: `RCX=18446744073709551615`
- manifest expected: `268435200`
- native: `268435200`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 (matches x=8)

- inputs: `RCX=72623859790382856`
- manifest expected: `9223372036854775799`
- native: `9223372036854775799`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `9223372036854775567`
- native: `9223372036854775567`
- lifted: `—`

## Source

```c
/* PC-state VM that shifts r right by (i+1) bits then XORs the byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = ~0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> (i + 1)) ^ (s & 0xFF);   // lshr ACCUMULATOR by counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynlshr_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_byte64_loop (shl accumulator by counter, ADD)
 *   - vm_bitfetch_window64_loop   (lshr INPUT by counter, OR fold)
 *   - vm_data_lshr64_loop         (lshr accumulator by byte data)
 *
 * Tests `lshr i64 %r, %(i+1)` (lshr accumulator by phi-tracked
 * counter expression) chained with byte XOR fold.  Initial r=~0
 * means the first iter shifts a saturated state down by 1 before
 * XOR with byte0.
 */
#include <stdio.h>
#include <stdint.h>

enum DlVmPc {
    DL_INIT_ALL = 0,
    DL_CHECK    = 1,
    DL_BODY     = 2,
    DL_INC      = 3,
    DL_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynlshr_accum_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DL_INIT_ALL;

    while (1) {
        if (pc == DL_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xFFFFFFFFFFFFFFFFull;
            i = 0ull;
            pc = DL_CHECK;
        } else if (pc == DL_CHECK) {
            pc = (i < n) ? DL_BODY : DL_HALT;
        } else if (pc == DL_BODY) {
            r = (r >> (i + 1ull)) ^ (s & 0xFFull);
            s = s >> 8;
            pc = DL_INC;
        } else if (pc == DL_INC) {
            i = i + 1ull;
            pc = DL_CHECK;
        } else if (pc == DL_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynlshr_accum_byte64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynlshr_accum_byte64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
