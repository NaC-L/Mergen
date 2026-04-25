# vm_byte_andfold64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byte_andfold64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byte_andfold64_loop.ll`
- **Symbol:** `vm_byte_andfold64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byte_andfold64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byte_andfold64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 n=1: 0xFF & 0=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | x=1 n=2: 0xFF&1=1; 1&0=0 |
| 3 | RCX=2 | 0 | 0 | 0 | yes | x=2 n=3: 2&0=0 |
| 4 | RCX=7 | 0 | 0 | 0 | yes | x=7 n=8: byte0=7 then 0s |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: 0xFF & 8=8 |
| 6 | RCX=3405691582 | 0 | 0 | 0 | yes | 0xCAFEBABE: n=7 high byte=0 |
| 7 | RCX=3735928559 | 0 | 0 | 0 | yes | 0xDEADBEEF: n=8 high byte=0 |
| 8 | RCX=18446744073709551615 | 255 | 255 | 255 | yes | all 0xFF: r stays 0xFF |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=18446460386757245432 | 248 | 248 | 248 | yes | 0xFFFEFDFCFBFAF9F8: n=1 byte0=0xF8=248 |

## Source

```c
/* PC-state VM that AND-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xFF;
 *   while (n) {
 *     r = r & (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_andfold64_loop_target.
 *
 * Distinct from:
 *   - vm_andsum_byte_idx64_loop (byte AND counter, ADD-folded)
 *   - vm_word_orfold64_loop     (OR fold, monotone INCREASING)
 *   - vm_byteprod64_loop        (multiplicative chain)
 *
 * Tests `and i64` chain at byte stride.  AND fold is monotone
 * DECREASING (only clears bits) - counterpart to OR's monotone
 * increasing.  Any zero byte clears the accumulator to 0.  All-FF
 * input preserves r=0xFF.
 */
#include <stdio.h>
#include <stdint.h>

enum BaVmPc {
    BA_INIT_ALL = 0,
    BA_CHECK    = 1,
    BA_BODY     = 2,
    BA_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_andfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BA_INIT_ALL;

    while (1) {
        if (pc == BA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xFFull;
            pc = BA_CHECK;
        } else if (pc == BA_CHECK) {
            pc = (n > 0ull) ? BA_BODY : BA_HALT;
        } else if (pc == BA_BODY) {
            r = r & (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BA_CHECK;
        } else if (pc == BA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_andfold64(0xFFFEFDFCFBFAF9F8)=%llu\n",
           (unsigned long long)vm_byte_andfold64_loop_target(0xFFFEFDFCFBFAF9F8ull));
    return 0;
}
```
