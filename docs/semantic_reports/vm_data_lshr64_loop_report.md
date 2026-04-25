# vm_data_lshr64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_data_lshr64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_data_lshr64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_data_lshr64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_data_lshr64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_data_lshr64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 18446744073709551615 | 18446744073709551615 | — | **no** | x=0 n=1: r=~0; (~0 >> 0) ^ 0 = ~0 |
| 2 | RCX=1 | 9223372036854775806 | 9223372036854775806 | — | **no** | x=1 n=2 |
| 3 | RCX=2 | 4611686018427387901 | 4611686018427387901 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 144115188075855864 | 144115188075855864 | — | **no** | x=7 n=8 |
| 5 | RCX=8 | 18446744073709551607 | 18446744073709551607 | — | **no** | x=8 n=1: ~0 >> 0 ^ 8 = 2^64-9 |
| 6 | RCX=3405691582 | 281474976710410 | 281474976710410 | — | **no** | 0xCAFEBABE: n=7 data-driven shifts |
| 7 | RCX=3735928559 | 1099511627555 | 1099511627555 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 1 | 1 | — | **no** | all 0xFF: shr by 7 each iter; final r=1 ^ 0xFF=0xFE wait actually 1 |
| 9 | RCX=72623859790382856 | 18446744073709551607 | 18446744073709551607 | — | **no** | 0x0102...0708: n=1 byte=8 |
| 10 | RCX=1311768467463790320 | 18446744073709551375 | 18446744073709551375 | — | **no** | 0x12345...EF0: n=1 byte=0xF0 |

## Failure detail

### case 1: x=0 n=1: r=~0; (~0 >> 0) ^ 0 = ~0

- inputs: `RCX=0`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 2: x=1 n=2

- inputs: `RCX=1`
- manifest expected: `9223372036854775806`
- native: `9223372036854775806`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `4611686018427387901`
- native: `4611686018427387901`
- lifted: `—`

### case 4: x=7 n=8

- inputs: `RCX=7`
- manifest expected: `144115188075855864`
- native: `144115188075855864`
- lifted: `—`

### case 5: x=8 n=1: ~0 >> 0 ^ 8 = 2^64-9

- inputs: `RCX=8`
- manifest expected: `18446744073709551607`
- native: `18446744073709551607`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 data-driven shifts

- inputs: `RCX=3405691582`
- manifest expected: `281474976710410`
- native: `281474976710410`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `1099511627555`
- native: `1099511627555`
- lifted: `—`

### case 8: all 0xFF: shr by 7 each iter; final r=1 ^ 0xFF=0xFE wait actually 1

- inputs: `RCX=18446744073709551615`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte=8

- inputs: `RCX=72623859790382856`
- manifest expected: `18446744073709551607`
- native: `18446744073709551607`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte=0xF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `18446744073709551375`
- native: `18446744073709551375`
- lifted: `—`

## Source

```c
/* PC-state VM with DATA-DEPENDENT right-shift amount inside the loop:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = ~0;     // start with all-1s
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = (r >> (b & 7)) ^ b;   // lshr amount comes from byte data
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_data_lshr64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (data-dependent SHL counterpart)
 *   - vm_bitfetch_window64_loop (lshr by loop counter)
 *   - vm_dyn_ashr64_loop      (ashr by loop counter)
 *
 * Tests `lshr i64 r, %byte_amount` (right-shift by byte-derived
 * amount).  Combined with XOR fold of the raw byte.  Initial r=~0
 * means the first iter shifts a saturated state down by a
 * data-driven amount before XOR.
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
uint64_t vm_data_lshr64_loop_target(uint64_t x) {
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
            uint64_t b = s & 0xFFull;
            r = (r >> (b & 7ull)) ^ b;
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
    printf("vm_data_lshr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_lshr64_loop_target(0xDEADBEEFull));
    return 0;
}
```
