# vm_notand_chain64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_notand_chain64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_notand_chain64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_notand_chain64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_notand_chain64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_notand_chain64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0: r stays 0 (NOT AND 0 = 0; xor i<<3 keeps in low bits but r=0&0) |
| 2 | RCX=1 | 9 | 9 | — | **no** | x=1 n=2: trace through 2 iters |
| 3 | RCX=2 | 16 | 16 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 63 | 63 | — | **no** | x=7 n=8: max trip |
| 5 | RCX=8 | 0 | 0 | — | **no** | x=8 n=1: (~8)&8=0; xor 0=0 |
| 6 | RCX=3405691582 | 56 | 56 | — | **no** | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3735928575 | 3735928575 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | all 0xFF: ~r is single-bit, AND with all-1 keeps it; eight xor i<<3 over [0..56] flips 8 bytes |
| 9 | RCX=72623859790382856 | 0 | 0 | — | **no** | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 0 | 0 | — | **no** | 0x12345...EF0: n=1 single iter (~x)&x=0 |

## Failure detail

### case 1: x=0: r stays 0 (NOT AND 0 = 0; xor i<<3 keeps in low bits but r=0&0)

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: trace through 2 iters

- inputs: `RCX=1`
- manifest expected: `9`
- native: `9`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `16`
- native: `16`
- lifted: `—`

### case 4: x=7 n=8: max trip

- inputs: `RCX=7`
- manifest expected: `63`
- native: `63`
- lifted: `—`

### case 5: x=8 n=1: (~8)&8=0; xor 0=0

- inputs: `RCX=8`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7

- inputs: `RCX=3405691582`
- manifest expected: `56`
- native: `56`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `3735928575`
- native: `3735928575`
- lifted: `—`

### case 8: all 0xFF: ~r is single-bit, AND with all-1 keeps it; eight xor i<<3 over [0..56] flips 8 bytes

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 9: 0x0102...0708: n=1 single iter

- inputs: `RCX=72623859790382856`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 single iter (~x)&x=0

- inputs: `RCX=1311768467463790320`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM running a NOT-AND chain with dynamic-shift xor:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (~r) & x;
 *     r = r ^ (i << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_notand_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_subxor_chain64_loop    (sub + shl + xor)
 *   - vm_negstep64_loop         (negate + add)
 *
 * Tests bitwise NOT (`xor i64 r, -1`) followed by AND with input,
 * then xor with `i << 3` where i is the loop-index phi.  Combines
 * the bitwise NOT/AND idiom (also known as `andn`) with a dynamic
 * left-shift xor.
 */
#include <stdio.h>
#include <stdint.h>

enum NaVmPc {
    NA_INIT_ALL = 0,
    NA_CHECK    = 1,
    NA_BODY     = 2,
    NA_INC      = 3,
    NA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_notand_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NA_INIT_ALL;

    while (1) {
        if (pc == NA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = NA_CHECK;
        } else if (pc == NA_CHECK) {
            pc = (i < n) ? NA_BODY : NA_HALT;
        } else if (pc == NA_BODY) {
            r = (~r) & x;
            r = r ^ (i << 3);
            pc = NA_INC;
        } else if (pc == NA_INC) {
            i = i + 1ull;
            pc = NA_CHECK;
        } else if (pc == NA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_notand_chain64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_notand_chain64_loop_target(0xDEADBEEFull));
    return 0;
}
```
