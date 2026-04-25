# vm_data_ashr64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_data_ashr64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_data_ashr64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_data_ashr64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_data_ashr64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_data_ashr64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 n=1: r=0; (0 >> 0) + 0 = 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 16 | 16 | — | **no** | x=8 n=1: 8 ashr 0 + 8 = 16 |
| 6 | RCX=3405691582 | 52233 | 52233 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 447 | 447 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 257 | 257 | — | **no** | all 0xFF: ashr fills 1s -> stable -1 + 0xFF, several iters |
| 9 | RCX=9223372036854775808 | 9223372036854775808 | 9223372036854775808 | — | **no** | x=2^63 n=1: ashr by 0=identity, +0=2^63 |
| 10 | RCX=1311768467463790320 | 1311768467463790560 | 1311768467463790560 | — | **no** | 0x12345...EF0: n=1 byte=0xF0=240; ashr 0; +240 |

## Failure detail

### case 1: x=0 n=1: r=0; (0 >> 0) + 0 = 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 contributes

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: 8 ashr 0 + 8 = 16

- inputs: `RCX=8`
- manifest expected: `16`
- native: `16`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `52233`
- native: `52233`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `447`
- native: `447`
- lifted: `—`

### case 8: all 0xFF: ashr fills 1s -> stable -1 + 0xFF, several iters

- inputs: `RCX=18446744073709551615`
- manifest expected: `257`
- native: `257`
- lifted: `—`

### case 9: x=2^63 n=1: ashr by 0=identity, +0=2^63

- inputs: `RCX=9223372036854775808`
- manifest expected: `9223372036854775808`
- native: `9223372036854775808`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte=0xF0=240; ashr 0; +240

- inputs: `RCX=1311768467463790320`
- manifest expected: `1311768467463790560`
- native: `1311768467463790560`
- lifted: `—`

## Source

```c
/* PC-state VM with DATA-DEPENDENT arithmetic right-shift amount:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     int amt = (int)(b & 7);
 *     r = (uint64_t)((int64_t)r >> amt) + b;   // ashr by byte amount
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_data_ashr64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (data-dependent SHL)
 *   - vm_data_lshr64_loop     (data-dependent LSHR)
 *   - vm_dyn_ashr64_loop      (ashr by loop counter, NOT byte data)
 *
 * Completes the data-dependent shift trio (shl / lshr / ashr).
 * Sign-extending right-shift by an amount that comes from the byte
 * stream propagates the high bit of the running r through iterations,
 * producing different fills than lshr for high-bit-set states.
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
uint64_t vm_data_ashr64_loop_target(uint64_t x) {
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
            uint64_t b   = s & 0xFFull;
            int      amt = (int)(b & 7ull);
            r = (uint64_t)((int64_t)r >> amt) + b;
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
    printf("vm_data_ashr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_ashr64_loop_target(0xDEADBEEFull));
    return 0;
}
```
