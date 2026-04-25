# vm_orxor_pair64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_orxor_pair64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_orxor_pair64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_orxor_pair64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_orxor_pair64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_orxor_pair64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 a=0 b=0 n=1: a\|b=0; b=0^0=0; ret 0 |
| 2 | RCX=1 | 7 | 7 | — | **no** | x=1 n=2: trace through 2 iters |
| 3 | RCX=2 | 100 | 100 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 7332103 | 7332103 | — | **no** | x=7 n=8: max trip |
| 5 | RCX=8 | 16 | 16 | — | **no** | x=8 n=1: a\|0=8; b=8^0=8; ret 16 |
| 6 | RCX=3405691582 | 437732809233088 | 437732809233088 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3937552892141111 | 3937552892141111 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 720599 | 720599 | — | **no** | all 0xFF: a\|b stays ~0; b evolves via XOR-mul *7 |
| 9 | RCX=72623859790382856 | 145247719580765712 | 145247719580765712 | — | **no** | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 2623536934927580640 | 2623536934927580640 | — | **no** | 0x12345...EF0: n=1 |

## Failure detail

### case 1: x=0 a=0 b=0 n=1: a|b=0; b=0^0=0; ret 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: trace through 2 iters

- inputs: `RCX=1`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `100`
- native: `100`
- lifted: `—`

### case 4: x=7 n=8: max trip

- inputs: `RCX=7`
- manifest expected: `7332103`
- native: `7332103`
- lifted: `—`

### case 5: x=8 n=1: a|0=8; b=8^0=8; ret 16

- inputs: `RCX=8`
- manifest expected: `16`
- native: `16`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `437732809233088`
- native: `437732809233088`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `3937552892141111`
- native: `3937552892141111`
- lifted: `—`

### case 8: all 0xFF: a|b stays ~0; b evolves via XOR-mul *7

- inputs: `RCX=18446744073709551615`
- manifest expected: `720599`
- native: `720599`
- lifted: `—`

### case 9: 0x0102...0708: n=1 single iter

- inputs: `RCX=72623859790382856`
- manifest expected: `145247719580765712`
- native: `145247719580765712`
- lifted: `—`

### case 10: 0x12345...EF0: n=1

- inputs: `RCX=1311768467463790320`
- manifest expected: `2623536934927580640`
- native: `2623536934927580640`
- lifted: `—`

## Source

```c
/* PC-state VM that runs a two-state OR/XOR-mul cross-feed:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t t = a;
 *     a = a | b;
 *     b = t ^ (b * 7);
 *   }
 *   return a + b;
 *
 * Lift target: vm_orxor_pair64_loop_target.
 *
 * Distinct from:
 *   - vm_pairmix64_loop          (two-state with add+mul-by-GR cross-feed)
 *   - vm_threestate_xormul64_loop (three-state cross-feed with mul-by-GR)
 *   - vm_orsum_byte_idx64_loop   (single-state OR fold over bytes)
 *
 * Tests an explicit temp barrier (`t = a`) so the OR (`a |= b`) and
 * XOR-mul (`b = t ^ b*7`) updates both see the original a value
 * before either is overwritten.  Combines monotone OR fold on `a`
 * with non-monotone XOR-mul evolution on `b`, returning a+b.
 */
#include <stdio.h>
#include <stdint.h>

enum OxVmPc {
    OX_INIT_ALL = 0,
    OX_CHECK    = 1,
    OX_BODY     = 2,
    OX_INC      = 3,
    OX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orxor_pair64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = OX_INIT_ALL;

    while (1) {
        if (pc == OX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = 0ull;
            i = 0ull;
            pc = OX_CHECK;
        } else if (pc == OX_CHECK) {
            pc = (i < n) ? OX_BODY : OX_HALT;
        } else if (pc == OX_BODY) {
            uint64_t t = a;
            a = a | b;
            b = t ^ (b * 7ull);
            pc = OX_INC;
        } else if (pc == OX_INC) {
            i = i + 1ull;
            pc = OX_CHECK;
        } else if (pc == OX_HALT) {
            return a + b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orxor_pair64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_orxor_pair64_loop_target(0xCAFEBABEull));
    return 0;
}
```
