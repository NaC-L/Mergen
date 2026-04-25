# vm_dynashr_accum_byte64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dynashr_accum_byte64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_dynashr_accum_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dynashr_accum_byte64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dynashr_accum_byte64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dynashr_accum_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 n=1: ashr 0=0 + 0=0 |
| 2 | RCX=1 | 0 | 0 | — | **no** | x=1 n=2: ashr 1>>1=0 + 1=1; ashr 1>>2=0 + 0=0 |
| 3 | RCX=2 | 0 | 0 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 0 | 0 | — | **no** | x=7 n=8: ashr collapses then bytes 0 |
| 5 | RCX=8 | 12 | 12 | — | **no** | x=8 n=1: ashr 8>>1=4 + 8=12 |
| 6 | RCX=3405691582 | 12 | 12 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 0 | 0 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 256 | 256 | — | **no** | all 0xFF: ashr fills 1s -> r=-1 each iter; final +0xFF*8 wraps via -1+sums |
| 9 | RCX=9223372036854775808 | 13835058055282163712 | 13835058055282163712 | — | **no** | x=2^63 n=1: ashr 2^63>>1=0xC000... + 0=2^63+2^62 |
| 10 | RCX=1311768467463790320 | 655884233731895400 | 655884233731895400 | — | **no** | 0x12345...EF0: n=1 single iter |

## Failure detail

### case 1: x=0 n=1: ashr 0=0 + 0=0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: ashr 1>>1=0 + 1=1; ashr 1>>2=0 + 0=0

- inputs: `RCX=1`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 4: x=7 n=8: ashr collapses then bytes 0

- inputs: `RCX=7`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 5: x=8 n=1: ashr 8>>1=4 + 8=12

- inputs: `RCX=8`
- manifest expected: `12`
- native: `12`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `12`
- native: `12`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: all 0xFF: ashr fills 1s -> r=-1 each iter; final +0xFF*8 wraps via -1+sums

- inputs: `RCX=18446744073709551615`
- manifest expected: `256`
- native: `256`
- lifted: `—`

### case 9: x=2^63 n=1: ashr 2^63>>1=0xC000... + 0=2^63+2^62

- inputs: `RCX=9223372036854775808`
- manifest expected: `13835058055282163712`
- native: `13835058055282163712`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 single iter

- inputs: `RCX=1311768467463790320`
- manifest expected: `655884233731895400`
- native: `655884233731895400`
- lifted: `—`

## Source

```c
/* PC-state VM that ASHRs r by (i+1) then adds the byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (uint64_t)((int64_t)r >> (i + 1)) + (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynashr_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_byte64_loop  (shl accumulator by counter)
 *   - vm_dynlshr_accum_byte64_loop (lshr accumulator by counter)
 *   - vm_data_ashr64_loop          (ashr accumulator by byte data)
 *
 * Completes the counter-driven accumulator-shift trio (shl/lshr/ashr).
 * Sign-extending right-shift propagates the high bit of running r
 * through iterations - high-bit-set seeds (e.g. 2^63) sign-extend
 * to all-1s before the byte add.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynashr_accum_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            r = (uint64_t)((int64_t)r >> (int)(i + 1ull)) + (s & 0xFFull);
            s = s >> 8;
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynashr_accum_byte64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_dynashr_accum_byte64_loop_target(0x8000000000000000ull));
    return 0;
}
```
