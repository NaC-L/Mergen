# vm_quad_byte_xor64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_quad_byte_xor64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_quad_byte_xor64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_quad_byte_xor64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_quad_byte_xor64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_quad_byte_xor64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: quad (1,0,0,0)=1; quad (0,0,0,0)=0 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=1: quad (2,0,0,0)=2 |
| 4 | RCX=3 | 3 | 3 | — | **no** | x=3 n=2: quad (3,0,0,0)=3 + quad (0,0,0,0)=0 |
| 5 | RCX=3405691582 | 48 | 48 | — | **no** | 0xCAFEBABE: n=1 quad (BE,BA,FE,CA): xor=0x30=48 |
| 6 | RCX=3735928559 | 34 | 34 | — | **no** | 0xDEADBEEF: n=2 first quad XOR + second quad (zeros) |
| 7 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF: 4 0xFF XOR cancel pairwise |
| 8 | RCX=72623859790382856 | 12 | 12 | — | **no** | 0x0102...0708: n=1 quad (8,7,6,5)=0xC=12 |
| 9 | RCX=1311768467463790320 | 8 | 8 | — | **no** | 0x12345...EF0: n=1 quad (F0,DE,BC,9A): xor low nibbles |
| 10 | RCX=18364758544493064720 | 0 | 0 | — | **no** | 0xFEDCBA9876543210: n=1 quad (10,32,54,76): even XOR cancels |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: quad (1,0,0,0)=1; quad (0,0,0,0)=0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=1: quad (2,0,0,0)=2

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=3 n=2: quad (3,0,0,0)=3 + quad (0,0,0,0)=0

- inputs: `RCX=3`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 5: 0xCAFEBABE: n=1 quad (BE,BA,FE,CA): xor=0x30=48

- inputs: `RCX=3405691582`
- manifest expected: `48`
- native: `48`
- lifted: `—`

### case 6: 0xDEADBEEF: n=2 first quad XOR + second quad (zeros)

- inputs: `RCX=3735928559`
- manifest expected: `34`
- native: `34`
- lifted: `—`

### case 7: all 0xFF: 4 0xFF XOR cancel pairwise

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: 0x0102...0708: n=1 quad (8,7,6,5)=0xC=12

- inputs: `RCX=72623859790382856`
- manifest expected: `12`
- native: `12`
- lifted: `—`

### case 9: 0x12345...EF0: n=1 quad (F0,DE,BC,9A): xor low nibbles

- inputs: `RCX=1311768467463790320`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0xFEDCBA9876543210: n=1 quad (10,32,54,76): even XOR cancels

- inputs: `RCX=18364758544493064720`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM that processes 4 bytes per iteration (32-bit stride):
 *
 *   n = (x & 1) + 1;     // 1..2 quad iterations
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b0 = s & 0xFF;
 *     uint64_t b1 = (s >> 8) & 0xFF;
 *     uint64_t b2 = (s >> 16) & 0xFF;
 *     uint64_t b3 = (s >> 24) & 0xFF;
 *     r = r + (b0 ^ b1 ^ b2 ^ b3);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_quad_byte_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_pair_xormul_byte64_loop (TWO bytes per iter)
 *   - All single-byte-per-iter samples
 *
 * Tests FOUR byte reads per iteration combined via 3 chained XORs
 * then ADD-folded into accumulator.  Wider 32-bit stride per iter
 * (advances s by 4 bytes).  Trip uses `& 1` so loop runs 1..2 times
 * consuming 4 bytes each.
 */
#include <stdio.h>
#include <stdint.h>

enum QbVmPc {
    QB_INIT_ALL = 0,
    QB_CHECK    = 1,
    QB_BODY     = 2,
    QB_INC      = 3,
    QB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_quad_byte_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = QB_INIT_ALL;

    while (1) {
        if (pc == QB_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = QB_CHECK;
        } else if (pc == QB_CHECK) {
            pc = (i < n) ? QB_BODY : QB_HALT;
        } else if (pc == QB_BODY) {
            uint64_t b0 = s & 0xFFull;
            uint64_t b1 = (s >> 8) & 0xFFull;
            uint64_t b2 = (s >> 16) & 0xFFull;
            uint64_t b3 = (s >> 24) & 0xFFull;
            r = r + (b0 ^ b1 ^ b2 ^ b3);
            s = s >> 32;
            pc = QB_INC;
        } else if (pc == QB_INC) {
            i = i + 1ull;
            pc = QB_CHECK;
        } else if (pc == QB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_quad_byte_xor64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_quad_byte_xor64_loop_target(0xCAFEBABEull));
    return 0;
}
```
