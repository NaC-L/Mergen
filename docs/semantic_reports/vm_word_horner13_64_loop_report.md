# vm_word_horner13_64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_word_horner13_64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_word_horner13_64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_word_horner13_64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_word_horner13_64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_word_horner13_64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 13 | 13 | — | **no** | x=1 n=2: 0*13+1=1; 1*13+0=13 |
| 3 | RCX=2 | 338 | 338 | — | **no** | x=2 n=3: 2 -> 26 -> 338 |
| 4 | RCX=3 | 6591 | 6591 | — | **no** | x=3 n=4: chain over 4 zero-padded iters |
| 5 | RCX=3405691582 | 8754772 | 8754772 | — | **no** | 0xCAFEBABE: n=3 words (BABE,CAFE,0) |
| 6 | RCX=3735928559 | 117021008 | 117021008 | — | **no** | 0xDEADBEEF: n=4 |
| 7 | RCX=18446744073709551615 | 155973300 | 155973300 | — | **no** | all 0xFF n=4 |
| 8 | RCX=72623859790382856 | 1800 | 1800 | — | **no** | 0x0102...0708: n=1 word=0x0708=1800 |
| 9 | RCX=1311768467463790320 | 57072 | 57072 | — | **no** | 0x12345...EF0: n=1 word=0xDEF0 |
| 10 | RCX=18364758544493064720 | 12816 | 12816 | — | **no** | 0xFEDCBA9876543210: n=1 word=0x3210 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 0*13+1=1; 1*13+0=13

- inputs: `RCX=1`
- manifest expected: `13`
- native: `13`
- lifted: `—`

### case 3: x=2 n=3: 2 -> 26 -> 338

- inputs: `RCX=2`
- manifest expected: `338`
- native: `338`
- lifted: `—`

### case 4: x=3 n=4: chain over 4 zero-padded iters

- inputs: `RCX=3`
- manifest expected: `6591`
- native: `6591`
- lifted: `—`

### case 5: 0xCAFEBABE: n=3 words (BABE,CAFE,0)

- inputs: `RCX=3405691582`
- manifest expected: `8754772`
- native: `8754772`
- lifted: `—`

### case 6: 0xDEADBEEF: n=4

- inputs: `RCX=3735928559`
- manifest expected: `117021008`
- native: `117021008`
- lifted: `—`

### case 7: all 0xFF n=4

- inputs: `RCX=18446744073709551615`
- manifest expected: `155973300`
- native: `155973300`
- lifted: `—`

### case 8: 0x0102...0708: n=1 word=0x0708=1800

- inputs: `RCX=72623859790382856`
- manifest expected: `1800`
- native: `1800`
- lifted: `—`

### case 9: 0x12345...EF0: n=1 word=0xDEF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `57072`
- native: `57072`
- lifted: `—`

### case 10: 0xFEDCBA9876543210: n=1 word=0x3210

- inputs: `RCX=18364758544493064720`
- manifest expected: `12816`
- native: `12816`
- lifted: `—`

## Source

```c
/* PC-state VM that runs Horner-style hash on u16 words with mul 13:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r * 13 + w;     // Horner on words
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_word_horner13_64_loop_target.
 *
 * Distinct from:
 *   - vm_mul3byte_chain64_loop (Horner on BYTES with mul 3)
 *   - vm_djb264_loop          (Horner on bytes with mul 33)
 *   - vm_word_xormul64_loop   (word self-multiply XOR)
 *   - vm_horner64_loop        (general polynomial)
 *
 * Tests Horner-style multiply-then-add chain on 16-bit word reads
 * (stride 16 bits) with multiplier 13.  Different stride width AND
 * different multiplier than existing byte-Horner samples.
 */
#include <stdio.h>
#include <stdint.h>

enum WhVmPc {
    WH_INIT_ALL = 0,
    WH_CHECK    = 1,
    WH_BODY     = 2,
    WH_INC      = 3,
    WH_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_horner13_64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WH_INIT_ALL;

    while (1) {
        if (pc == WH_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WH_CHECK;
        } else if (pc == WH_CHECK) {
            pc = (i < n) ? WH_BODY : WH_HALT;
        } else if (pc == WH_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r * 13ull + w;
            s = s >> 16;
            pc = WH_INC;
        } else if (pc == WH_INC) {
            i = i + 1ull;
            pc = WH_CHECK;
        } else if (pc == WH_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_horner13_64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_horner13_64_loop_target(0xCAFEBABEull));
    return 0;
}
```
