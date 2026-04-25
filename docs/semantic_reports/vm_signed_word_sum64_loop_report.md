# vm_signed_word_sum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_word_sum64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_signed_word_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_word_sum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_signed_word_sum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_word_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: word=1 +0 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3 |
| 4 | RCX=3 | 3 | 3 | — | **no** | x=3 n=4: 3 + 0+0+0 |
| 5 | RCX=3405691582 | 18446744073709520316 | 18446744073709520316 | — | **no** | 0xCAFEBABE: n=3 mixed-sign words |
| 6 | RCX=3735928559 | 18446744073709526428 | 18446744073709526428 | — | **no** | 0xDEADBEEF: n=4 mostly negative words |
| 7 | RCX=18446744073709551615 | 18446744073709551612 | 18446744073709551612 | — | **no** | all 0xFF n=4: 4 sext(-1) -> -4 in u64 |
| 8 | RCX=72623859790382856 | 1800 | 1800 | — | **no** | 0x0102...0708: n=1 word=0x0708=+1800 |
| 9 | RCX=1311768467463790320 | 18446744073709543152 | 18446744073709543152 | — | **no** | 0x12345...EF0: n=1 word=0xDEF0 sext negative |
| 10 | RCX=2147516416 | 18446744073709518848 | 18446744073709518848 | — | **no** | 0x80008000: n=1 lower word=0x8000=-32768 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: word=1 +0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=3 n=4: 3 + 0+0+0

- inputs: `RCX=3`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 5: 0xCAFEBABE: n=3 mixed-sign words

- inputs: `RCX=3405691582`
- manifest expected: `18446744073709520316`
- native: `18446744073709520316`
- lifted: `—`

### case 6: 0xDEADBEEF: n=4 mostly negative words

- inputs: `RCX=3735928559`
- manifest expected: `18446744073709526428`
- native: `18446744073709526428`
- lifted: `—`

### case 7: all 0xFF n=4: 4 sext(-1) -> -4 in u64

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551612`
- native: `18446744073709551612`
- lifted: `—`

### case 8: 0x0102...0708: n=1 word=0x0708=+1800

- inputs: `RCX=72623859790382856`
- manifest expected: `1800`
- native: `1800`
- lifted: `—`

### case 9: 0x12345...EF0: n=1 word=0xDEF0 sext negative

- inputs: `RCX=1311768467463790320`
- manifest expected: `18446744073709543152`
- native: `18446744073709543152`
- lifted: `—`

### case 10: 0x80008000: n=1 lower word=0x8000=-32768

- inputs: `RCX=2147516416`
- manifest expected: `18446744073709518848`
- native: `18446744073709518848`
- lifted: `—`

## Source

```c
/* PC-state VM that sums sext-i16 words per iteration:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     r = r + (int64_t)sw;     // sext i16 -> i64
 *     s >>= 16;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signed_word_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop (sext-i8 byte sum, 8-bit stride)
 *   - vm_signed_dword_sum64_loop (sext-i32 dword sum, 32-bit stride)
 *
 * Fills the i16 middle width and completes the sext-width trio
 * (i8/i16/i32 -> i64).  Word-stride consumption with high-bit-set
 * words sign-extending to negative i64.
 */
#include <stdio.h>
#include <stdint.h>

enum SwVmPc {
    SW_INIT_ALL = 0,
    SW_CHECK    = 1,
    SW_BODY     = 2,
    SW_INC      = 3,
    SW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signed_word_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = SW_INIT_ALL;

    while (1) {
        if (pc == SW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = SW_CHECK;
        } else if (pc == SW_CHECK) {
            pc = (i < n) ? SW_BODY : SW_HALT;
        } else if (pc == SW_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            r = r + (int64_t)sw;
            s = s >> 16;
            pc = SW_INC;
        } else if (pc == SW_INC) {
            i = i + 1ull;
            pc = SW_CHECK;
        } else if (pc == SW_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_word_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signed_word_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
