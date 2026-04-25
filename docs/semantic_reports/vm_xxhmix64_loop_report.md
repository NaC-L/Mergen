# vm_xxhmix64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xxhmix64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xxhmix64_loop.ll`
- **Symbol:** `vm_xxhmix64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xxhmix64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xxhmix64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 4278604620067964124 | 4278604620067964124 | 4278604620067964124 | yes | x=0 n=1: hash of one zero byte + fold |
| 2 | RCX=1 | 6887135554585425544 | 6887135554585425544 | 6887135554585425544 | yes | x=1 n=2 |
| 3 | RCX=2 | 4021941542279809536 | 4021941542279809536 | 4021941542279809536 | yes | x=2 n=3 |
| 4 | RCX=7 | 17601424563760100313 | 17601424563760100313 | 17601424563760100313 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 2723330127315496288 | 2723330127315496288 | 2723330127315496288 | yes | x=8 n=1: byte 8 alone |
| 6 | RCX=3405691582 | 10406358633903240148 | 10406358633903240148 | 10406358633903240148 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 15341399812983602461 | 15341399812983602461 | 15341399812983602461 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 2945657518212642756 | 2945657518212642756 | 2945657518212642756 | yes | all 0xFF: 8 bytes of 0xFF |
| 9 | RCX=72623859790382856 | 2723330127315496288 | 2723330127315496288 | 2723330127315496288 | yes | 0x0102...0708: n=1 byte 0x08 (matches x=8) |
| 10 | RCX=1311768467463790320 | 734955951970954196 | 734955951970954196 | 734955951970954196 | yes | 0x12345...EF0: n=1 byte 0xF0 |

## Source

```c
/* PC-state VM running an xxhash-style per-byte mix chain over n=(x&7)+1
 * bytes, with a final xor-fold:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCAFEBABEDEADBEEF;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFF)) * 0xC2B2AE3D27D4EB4Full;   // xxhash PRIME64_3
 *     s >>= 8;
 *   }
 *   r = r ^ (r >> 33);
 *   return r;
 *
 * Lift target: vm_xxhmix64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop      (xor-then-multiply by 40-bit FNV prime)
 *   - vm_murmurstep64_loop (no byte windowing; xor with x each iter)
 *   - vm_djb264_loop       (additive *33)
 *   - vm_horner64_loop     (polynomial)
 *
 * Tests xor-then-mul with a 64-bit xxhash multiplier per byte, then a
 * final xor-fold by lshr 33 outside the loop.  Different magic
 * constant from FNV (0x100000001B3) and Murmur (0xC6A4A7935BD1E995).
 */
#include <stdio.h>
#include <stdint.h>

enum XxVmPc {
    XX_INIT_ALL = 0,
    XX_CHECK    = 1,
    XX_MIX      = 2,
    XX_SHIFT    = 3,
    XX_INC      = 4,
    XX_FOLD     = 5,
    XX_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_xxhmix64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XX_INIT_ALL;

    while (1) {
        if (pc == XX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCAFEBABEDEADBEEFull;
            i = 0ull;
            pc = XX_CHECK;
        } else if (pc == XX_CHECK) {
            pc = (i < n) ? XX_MIX : XX_FOLD;
        } else if (pc == XX_MIX) {
            r = (r ^ (s & 0xFFull)) * 0xC2B2AE3D27D4EB4Full;
            pc = XX_SHIFT;
        } else if (pc == XX_SHIFT) {
            s = s >> 8;
            pc = XX_INC;
        } else if (pc == XX_INC) {
            i = i + 1ull;
            pc = XX_CHECK;
        } else if (pc == XX_FOLD) {
            r = r ^ (r >> 33);
            pc = XX_HALT;
        } else if (pc == XX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xxhmix64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xxhmix64_loop_target(0xCAFEBABEull));
    return 0;
}
```
