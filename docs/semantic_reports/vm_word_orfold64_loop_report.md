# vm_word_orfold64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_word_orfold64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_word_orfold64_loop.ll`
- **Symbol:** `vm_word_orfold64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_word_orfold64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_word_orfold64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: words [1,0] |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=3 | 3 | 3 | 3 | yes | x=3 n=4: words [3,0,0,0] |
| 5 | RCX=3405691582 | 64254 | 64254 | 64254 | yes | 0xCAFEBABE: n=3 words BABE\|CAFE\|0 = 0xFAFE |
| 6 | RCX=3735928559 | 65263 | 65263 | 65263 | yes | 0xDEADBEEF: n=4 words BEEF\|DEAD\|0\|0 = 0xFEEF |
| 7 | RCX=18446744073709551615 | 65535 | 65535 | 65535 | yes | all 0xFF: 0xFFFF |
| 8 | RCX=72623859790382856 | 1800 | 1800 | 1800 | yes | 0x0102...0708: n=1 word=0x0708=1800 |
| 9 | RCX=1311768467463790320 | 57072 | 57072 | 57072 | yes | 0x12345...EF0: n=1 word=0xDEF0 |
| 10 | RCX=18364758544493064720 | 12816 | 12816 | 12816 | yes | 0xFEDCBA9876543210: n=1 word=0x3210 |

## Source

```c
/* PC-state VM that OR-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r | (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_orfold64_loop_target.
 *
 * Distinct from:
 *   - vm_orsum_byte_idx64_loop (byte | counter, 8-bit stride)
 *   - vm_word_xormul64_loop    (word self-multiply XOR fold)
 *   - vm_word_horner13_64_loop (word Horner with mul 13)
 *
 * Tests `or i64` chain at 16-bit word stride.  OR is monotone (only
 * sets bits), so result is bitwise-OR of all consumed words.  4
 * stateful slots (n,s,r + implicit) with n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum WoVmPc {
    WO_INIT_ALL = 0,
    WO_CHECK    = 1,
    WO_BODY     = 2,
    WO_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_orfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WO_INIT_ALL;

    while (1) {
        if (pc == WO_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WO_CHECK;
        } else if (pc == WO_CHECK) {
            pc = (n > 0ull) ? WO_BODY : WO_HALT;
        } else if (pc == WO_BODY) {
            r = r | (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WO_CHECK;
        } else if (pc == WO_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_orfold64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_orfold64_loop_target(0xCAFEBABEull));
    return 0;
}
```
