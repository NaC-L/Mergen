# vm_mul3byte_chain64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_mul3byte_chain64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_mul3byte_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_mul3byte_chain64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_mul3byte_chain64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_mul3byte_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 3 | 3 | — | **no** | x=1 n=2: 0*3+1=1; 1*3+0=3 |
| 3 | RCX=2 | 18 | 18 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 15309 | 15309 | — | **no** | x=7 n=8: max trip |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: 0*3+8=8 |
| 6 | RCX=3405691582 | 209736 | 209736 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 721224 | 721224 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 836400 | 836400 | — | **no** | all 0xFF: hash 0xFF*8 |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 0*3+1=1; 1*3+0=3

- inputs: `RCX=1`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `18`
- native: `18`
- lifted: `—`

### case 4: x=7 n=8: max trip

- inputs: `RCX=7`
- manifest expected: `15309`
- native: `15309`
- lifted: `—`

### case 5: x=8 n=1: 0*3+8=8

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `209736`
- native: `209736`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `721224`
- native: `721224`
- lifted: `—`

### case 8: all 0xFF: hash 0xFF*8

- inputs: `RCX=18446744073709551615`
- manifest expected: `836400`
- native: `836400`
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
/* PC-state VM that runs Horner-style hash with multiplier 3:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r * 3 + (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_mul3byte_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop          (multiplier *33 hash)
 *   - vm_fnv1a64_loop         (multiplier *FNV_PRIME after xor)
 *   - vm_horner64_loop        (general polynomial)
 *   - vm_xormuladd_chain64_loop (mul + xor + add, different ops)
 *
 * Tests `mul i64 r, 3` (small-constant multiplier - lifter likely
 * keeps as raw mul rather than lea-by-3 or shift+add fold).  Each
 * iter: multiply by 3 then add the next byte.  Variant on the
 * Horner polynomial evaluation pattern with a non-power-of-2
 * coefficient.
 */
#include <stdio.h>
#include <stdint.h>

enum M3VmPc {
    M3_INIT_ALL = 0,
    M3_CHECK    = 1,
    M3_BODY     = 2,
    M3_INC      = 3,
    M3_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_mul3byte_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = M3_INIT_ALL;

    while (1) {
        if (pc == M3_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = M3_CHECK;
        } else if (pc == M3_CHECK) {
            pc = (i < n) ? M3_BODY : M3_HALT;
        } else if (pc == M3_BODY) {
            r = r * 3ull + (s & 0xFFull);
            s = s >> 8;
            pc = M3_INC;
        } else if (pc == M3_INC) {
            i = i + 1ull;
            pc = M3_CHECK;
        } else if (pc == M3_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_mul3byte_chain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_mul3byte_chain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
