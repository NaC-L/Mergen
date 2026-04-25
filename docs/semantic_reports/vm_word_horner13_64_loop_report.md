# vm_word_horner13_64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_word_horner13_64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_word_horner13_64_loop.ll`
- **Symbol:** `vm_word_horner13_64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_word_horner13_64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_word_horner13_64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 13 | 13 | 13 | yes | x=1 n=2: 0*13+1=1; 1*13+0=13 |
| 3 | RCX=2 | 338 | 338 | 338 | yes | x=2 n=3: 2 -> 26 -> 338 |
| 4 | RCX=3 | 6591 | 6591 | 6591 | yes | x=3 n=4: chain over 4 zero-padded iters |
| 5 | RCX=3405691582 | 8754772 | 8754772 | 8754772 | yes | 0xCAFEBABE: n=3 words (BABE,CAFE,0) |
| 6 | RCX=3735928559 | 117021008 | 117021008 | 117021008 | yes | 0xDEADBEEF: n=4 |
| 7 | RCX=18446744073709551615 | 155973300 | 155973300 | 155973300 | yes | all 0xFF n=4 |
| 8 | RCX=72623859790382856 | 1800 | 1800 | 1800 | yes | 0x0102...0708: n=1 word=0x0708=1800 |
| 9 | RCX=1311768467463790320 | 57072 | 57072 | 57072 | yes | 0x12345...EF0: n=1 word=0xDEF0 |
| 10 | RCX=18364758544493064720 | 12816 | 12816 | 12816 | yes | 0xFEDCBA9876543210: n=1 word=0x3210 |

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
