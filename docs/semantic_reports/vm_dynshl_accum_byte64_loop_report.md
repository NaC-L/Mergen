# vm_dynshl_accum_byte64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dynshl_accum_byte64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_dynshl_accum_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dynshl_accum_byte64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dynshl_accum_byte64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dynshl_accum_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 4 | 4 | — | **no** | x=1 n=2: (0<<1)+1=1; (1<<2)+0=4 |
| 3 | RCX=2 | 64 | 64 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 240518168576 | 240518168576 | — | **no** | x=7 n=8: max trip |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: (0<<1)+8=8 |
| 6 | RCX=3405691582 | 32860798976 | 32860798976 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 10044720545792 | 10044720545792 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 11243626725375 | 11243626725375 | — | **no** | all 0xFF n=8: cumulative shift 36 bits + 0xFF bytes |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: (0<<1)+1=1; (1<<2)+0=4

- inputs: `RCX=1`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `64`
- native: `64`
- lifted: `—`

### case 4: x=7 n=8: max trip

- inputs: `RCX=7`
- manifest expected: `240518168576`
- native: `240518168576`
- lifted: `—`

### case 5: x=8 n=1: (0<<1)+8=8

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `32860798976`
- native: `32860798976`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `10044720545792`
- native: `10044720545792`
- lifted: `—`

### case 8: all 0xFF n=8: cumulative shift 36 bits + 0xFF bytes

- inputs: `RCX=18446744073709551615`
- manifest expected: `11243626725375`
- native: `11243626725375`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `240`
- native: `240`
- lifted: `—`

## Source

```c
/* PC-state VM that builds r by shifting it left by (i+1) bits then
 * adding the next byte over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << (i + 1)) + (s & 0xFF);   // shl ACCUMULATOR by counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop     (shl BYTE by counter, fixed-width chunk)
 *   - vm_byteshl3_xor64_loop    (shl byte by i*3, XOR-folded)
 *   - vm_byteshl_data64_loop    (data-dependent shl on accumulator)
 *
 * Tests `shl i64 %r, %(i+1)` (shift ACCUMULATOR by phi-tracked counter
 * rather than shifting the byte) plus byte ADD.  Each iter the
 * accumulator grows by (i+1) bits; cumulative shift is 1+2+...+n.
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
uint64_t vm_dynshl_accum_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            r = (r << (i + 1ull)) + (s & 0xFFull);
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
    printf("vm_dynshl_accum_byte64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynshl_accum_byte64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
