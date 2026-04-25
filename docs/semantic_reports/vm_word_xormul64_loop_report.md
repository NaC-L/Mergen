# vm_word_xormul64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_word_xormul64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_word_xormul64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_word_xormul64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_word_xormul64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_word_xormul64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: w=1, 1^1=1; w=0 |
| 3 | RCX=2 | 4 | 4 | — | **no** | x=2 n=3: 2*2=4 |
| 4 | RCX=3 | 9 | 9 | — | **no** | x=3 n=4: 3*3=9 |
| 5 | RCX=3405691582 | 684552448 | 684552448 | — | **no** | 0xCAFEBABE: n=3 words (BABE,CAFE,0) |
| 6 | RCX=3735928559 | 1339499464 | 1339499464 | — | **no** | 0xDEADBEEF: n=4 |
| 7 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF: 4 XOR of 0xFFFE0001 cancel pairwise |
| 8 | RCX=72623859790382856 | 3240000 | 3240000 | — | **no** | 0x0102...0708: n=1 word=0x0708 squared |
| 9 | RCX=1311768467463790320 | 3257213184 | 3257213184 | — | **no** | 0x12345...EF0: n=1 word=0xDEF0 squared |
| 10 | RCX=18364758544493064720 | 164249856 | 164249856 | — | **no** | 0xFEDCBA9876543210: n=1 word=0x3210 squared |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: w=1, 1^1=1; w=0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: 2*2=4

- inputs: `RCX=2`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 4: x=3 n=4: 3*3=9

- inputs: `RCX=3`
- manifest expected: `9`
- native: `9`
- lifted: `—`

### case 5: 0xCAFEBABE: n=3 words (BABE,CAFE,0)

- inputs: `RCX=3405691582`
- manifest expected: `684552448`
- native: `684552448`
- lifted: `—`

### case 6: 0xDEADBEEF: n=4

- inputs: `RCX=3735928559`
- manifest expected: `1339499464`
- native: `1339499464`
- lifted: `—`

### case 7: all 0xFF: 4 XOR of 0xFFFE0001 cancel pairwise

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: 0x0102...0708: n=1 word=0x0708 squared

- inputs: `RCX=72623859790382856`
- manifest expected: `3240000`
- native: `3240000`
- lifted: `—`

### case 9: 0x12345...EF0: n=1 word=0xDEF0 squared

- inputs: `RCX=1311768467463790320`
- manifest expected: `3257213184`
- native: `3257213184`
- lifted: `—`

### case 10: 0xFEDCBA9876543210: n=1 word=0x3210 squared

- inputs: `RCX=18364758544493064720`
- manifest expected: `164249856`
- native: `164249856`
- lifted: `—`

## Source

```c
/* PC-state VM that processes u16 words per iteration (16-bit stride):
 *
 *   n = (x & 3) + 1;     // 1..4 word iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r ^ (w * w);    // u16 squared, XOR-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_word_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop     (byte squared, ADD-folded - 8-bit stride)
 *   - vm_pair_xormul_byte64_loop (2 BYTES per iter - 16-bit stride but byte ops)
 *   - vm_quad_byte_xor64_loop  (4 bytes per iter, 32-bit stride)
 *
 * Tests u16 (zext-i16) self-multiply per iteration with XOR fold.
 * Word-stride consumption with `& 0xFFFF` mask + lshr 16 advance.
 * All-0xFF input: each iter w=0xFFFF, w*w=0xFFFE0001, four XORs cancel.
 */
#include <stdio.h>
#include <stdint.h>

enum WxVmPc {
    WX_INIT_ALL = 0,
    WX_CHECK    = 1,
    WX_BODY     = 2,
    WX_INC      = 3,
    WX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WX_INIT_ALL;

    while (1) {
        if (pc == WX_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WX_CHECK;
        } else if (pc == WX_CHECK) {
            pc = (i < n) ? WX_BODY : WX_HALT;
        } else if (pc == WX_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r ^ (w * w);
            s = s >> 16;
            pc = WX_INC;
        } else if (pc == WX_INC) {
            i = i + 1ull;
            pc = WX_CHECK;
        } else if (pc == WX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
```
