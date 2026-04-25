# vm_word_range64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_word_range64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_word_range64_loop.ll`
- **Symbol:** `vm_word_range64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_word_range64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_word_range64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> mx=mn=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: words [1,0] -> mx=1 mn=0 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=3 | 3 | 3 | 3 | yes | x=3 n=4: words [3,0,0,0] -> 3-0 |
| 5 | RCX=3405691582 | 51966 | 51966 | 51966 | yes | 0xCAFEBABE: n=3 words BABE,CAFE,0 -> max=0xCAFE |
| 6 | RCX=3735928559 | 57005 | 57005 | 57005 | yes | 0xDEADBEEF: n=4 words BEEF,DEAD,0,0 -> max=0xDEAD |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=0xFFFF |
| 8 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 single word |
| 9 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 single word |
| 10 | RCX=18364758544493064720 | 0 | 0 | 0 | yes | 0xFEDCBA9876543210: n=1 single word |

## Source

```c
/* PC-state VM that tracks running min and max of u16 words and returns
 * (max - min) over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; mn = 0xFFFF; mx = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     if (w > mx) mx = w;
 *     if (w < mn) mn = w;
 *     s >>= 16;
 *     n--;
 *   }
 *   return mx - mn;
 *
 * Lift target: vm_word_range64_loop_target.
 *
 * Distinct from:
 *   - vm_byterange64_loop (u8 byte stream, 8-bit stride)
 *   - vm_signed_byterange64_loop (signed bytes, raw cmp)
 *   - vm_bytemax64_loop (u8 max only)
 *
 * Tests u16 cmp-driven reductions (umax/umin) at 16-bit stride.
 * Uses n-decrement loop control (no separate i counter) to keep the
 * stateful slot count low and avoid the byteposmax-style pseudo-stack
 * init failure observed when adding a 5th slot.
 */
#include <stdio.h>
#include <stdint.h>

enum WrVmPc {
    WR_INIT_ALL = 0,
    WR_CHECK    = 1,
    WR_BODY     = 2,
    WR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = WR_INIT_ALL;

    while (1) {
        if (pc == WR_INIT_ALL) {
            n  = (x & 3ull) + 1ull;
            s  = x;
            mn = 0xFFFFull;
            mx = 0ull;
            pc = WR_CHECK;
        } else if (pc == WR_CHECK) {
            pc = (n > 0ull) ? WR_BODY : WR_HALT;
        } else if (pc == WR_BODY) {
            uint64_t w = s & 0xFFFFull;
            mx = (w > mx) ? w : mx;
            mn = (w < mn) ? w : mn;
            s = s >> 16;
            n = n - 1ull;
            pc = WR_CHECK;
        } else if (pc == WR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_range64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_range64_loop_target(0xCAFEBABEull));
    return 0;
}
```
