# vm_uintadd_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_uintadd_byte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_uintadd_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_uintadd_byte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_uintadd_byte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_uintadd_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: 1*1 + 0*2 = 1 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3: 2*1=2 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1 |
| 6 | RCX=3405691582 | 2132 | 2132 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 2026 | 2026 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 9180 | 9180 | — | **no** | all 0xFF n=8: 0xFF * (1+2+...+8) = 0xFF*36=9180 |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 (matches x=8) |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 *1=240 (DIFFERENT from signed-sext -16) |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1*1 + 0*2 = 1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: 2*1=2

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
- manifest expected: `2132`
- native: `2132`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `2026`
- native: `2026`
- lifted: `—`

### case 8: all 0xFF n=8: 0xFF * (1+2+...+8) = 0xFF*36=9180

- inputs: `RCX=18446744073709551615`
- manifest expected: `9180`
- native: `9180`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 (matches x=8)

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0 *1=240 (DIFFERENT from signed-sext -16)

- inputs: `RCX=1311768467463790320`
- manifest expected: `240`
- native: `240`
- lifted: `—`

## Source

```c
/* PC-state VM that ADDs unsigned-byte * counter into the accumulator
 * over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + (s & 0xFF) * (i + 1);   // u8 zext * counter, ADD-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_uintadd_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop      (signed sext byte * counter, ADD-folded)
 *   - vm_xormul_byte_idx64_loop   (unsigned zext byte * counter, XOR-folded)
 *   - vm_signedxor_byte_idx64_loop (signed sext byte * counter, XOR-folded)
 *
 * Fills the zext+ADD cell - completes the per-byte * counter matrix
 * across all four (zext/sext) x (ADD/XOR) cells.  All-0xFF input
 * accumulates 0xFF * (1+2+...+8) = 0xFF * 36 = 9180 (positive, no
 * sign-extension into upper bits).
 */
#include <stdio.h>
#include <stdint.h>

enum UbVmPc {
    UB_INIT_ALL = 0,
    UB_CHECK    = 1,
    UB_BODY     = 2,
    UB_INC      = 3,
    UB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_uintadd_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = UB_INIT_ALL;

    while (1) {
        if (pc == UB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = UB_CHECK;
        } else if (pc == UB_CHECK) {
            pc = (i < n) ? UB_BODY : UB_HALT;
        } else if (pc == UB_BODY) {
            r = r + (s & 0xFFull) * (i + 1ull);
            s = s >> 8;
            pc = UB_INC;
        } else if (pc == UB_INC) {
            i = i + 1ull;
            pc = UB_CHECK;
        } else if (pc == UB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_uintadd_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_uintadd_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
