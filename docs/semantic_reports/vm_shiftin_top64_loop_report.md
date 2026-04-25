# vm_shiftin_top64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_shiftin_top64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_shiftin_top64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_shiftin_top64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_shiftin_top64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_shiftin_top64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 281474976710656 | 281474976710656 | — | **no** | x=1 n=2: byte0=1 << 56=2^56; >>8 then OR byte1=0 << 56 |
| 3 | RCX=2 | 2199023255552 | 2199023255552 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: byte0=7 ends up at byte 0 after 8 right-shifts |
| 5 | RCX=8 | 576460752303423488 | 576460752303423488 | — | **no** | x=8 n=1: 8 << 56 |
| 6 | RCX=3405691582 | 871857044992 | 871857044992 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3735928559 | 3735928559 | — | **no** | 0xDEADBEEF: n=8 - all bytes traverse top->bottom; result equals input low 32 bits |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | all 0xFF n=8: palindrome invariant |
| 9 | RCX=72623859790382856 | 576460752303423488 | 576460752303423488 | — | **no** | 0x0102...0708: n=1 byte0=8 << 56 (matches x=8) |
| 10 | RCX=1311768467463790320 | 17293822569102704640 | 17293822569102704640 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 << 56 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: byte0=1 << 56=2^56; >>8 then OR byte1=0 << 56

- inputs: `RCX=1`
- manifest expected: `281474976710656`
- native: `281474976710656`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `2199023255552`
- native: `2199023255552`
- lifted: `—`

### case 4: x=7 n=8: byte0=7 ends up at byte 0 after 8 right-shifts

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: 8 << 56

- inputs: `RCX=8`
- manifest expected: `576460752303423488`
- native: `576460752303423488`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `871857044992`
- native: `871857044992`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8 - all bytes traverse top->bottom; result equals input low 32 bits

- inputs: `RCX=3735928559`
- manifest expected: `3735928559`
- native: `3735928559`
- lifted: `—`

### case 8: all 0xFF n=8: palindrome invariant

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 << 56 (matches x=8)

- inputs: `RCX=72623859790382856`
- manifest expected: `576460752303423488`
- native: `576460752303423488`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0 << 56

- inputs: `RCX=1311768467463790320`
- manifest expected: `17293822569102704640`
- native: `17293822569102704640`
- lifted: `—`

## Source

```c
/* PC-state VM that builds r as a shift register fed from the top:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> 8) | ((s & 0xFF) << 56);   // shift in byte at top
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_shiftin_top64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (shl-or pack from low end)
 *   - vm_nibrev_window64_loop  (4-bit shift-or pack)
 *   - vm_byte_loop / vm_xorbytes64_loop (no shift register pattern)
 *
 * Tests `lshr i64 r, 8 | shl i64 byte, 56` shift-register update
 * pattern.  After n=8 iterations with all-FF input, r is preserved
 * (palindrome invariant); for n < 8 the upper bytes of r are filled
 * with x's lower bytes shifted into MSB position one at a time.
 */
#include <stdio.h>
#include <stdint.h>

enum StVmPc {
    ST_INIT_ALL = 0,
    ST_CHECK    = 1,
    ST_BODY     = 2,
    ST_INC      = 3,
    ST_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_shiftin_top64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ST_INIT_ALL;

    while (1) {
        if (pc == ST_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY : ST_HALT;
        } else if (pc == ST_BODY) {
            r = (r >> 8) | ((s & 0xFFull) << 56);
            s = s >> 8;
            pc = ST_INC;
        } else if (pc == ST_INC) {
            i = i + 1ull;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_shiftin_top64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_shiftin_top64_loop_target(0xDEADBEEFull));
    return 0;
}
```
