# vm_xormul_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xormul_byte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_xormul_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xormul_byte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_xormul_byte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xormul_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: byte0=1 *1 ^ byte1=0 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1 |
| 6 | RCX=3405691582 | 24 | 24 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 236 | 236 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF: n=8 -> XOR of 0xFF*1..0xFF*8 cancels to 0 (sum of 1..8=36 even count) |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 (matches x=8) |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: byte0=1 *1 ^ byte1=0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `24`
- native: `24`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `236`
- native: `236`
- lifted: `—`

### case 8: all 0xFF: n=8 -> XOR of 0xFF*1..0xFF*8 cancels to 0 (sum of 1..8=36 even count)

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 (matches x=8)

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
/* PC-state VM that XORs scaled bytes into the accumulator across
 * n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) * (i + 1));   // unsigned byte * counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormul_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop  (signed-byte sext + ADD accumulator)
 *   - vm_byteparity64_loop    (1-bit parity, no scaling)
 *   - vm_xorbytes64_loop      (XOR of bytes, no scaling)
 *
 * Tests unsigned byte (zext-i8) multiplied by dynamic counter (i+1)
 * folded into the accumulator via XOR rather than ADD.  The output
 * stays small for inputs whose bytes XOR to 0 after scaling (e.g.
 * all-0xFF cancels by symmetry of *1 ^ *2 ^ ... ^ *8 with same byte).
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_INIT_ALL = 0,
    XB_CHECK    = 1,
    XB_BODY     = 2,
    XB_INC      = 3,
    XB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormul_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XB_INIT_ALL;

    while (1) {
        if (pc == XB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XB_CHECK;
        } else if (pc == XB_CHECK) {
            pc = (i < n) ? XB_BODY : XB_HALT;
        } else if (pc == XB_BODY) {
            r = r ^ ((s & 0xFFull) * (i + 1ull));
            s = s >> 8;
            pc = XB_INC;
        } else if (pc == XB_INC) {
            i = i + 1ull;
            pc = XB_CHECK;
        } else if (pc == XB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormul_byte_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormul_byte_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
```
