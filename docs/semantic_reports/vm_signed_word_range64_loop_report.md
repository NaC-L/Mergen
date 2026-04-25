# vm_signed_word_range64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_word_range64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signed_word_range64_loop.ll`
- **Symbol:** `vm_signed_word_range64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_word_range64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_word_range64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> mx=mn=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: words [+1,0] -> 1-0 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=3 | 3 | 3 | 3 | yes | x=3 n=4 |
| 5 | RCX=3405691582 | 17730 | 17730 | 17730 | yes | 0xCAFEBABE: n=3 mixed-sign words |
| 6 | RCX=3735928559 | 16657 | 16657 | 16657 | yes | 0xDEADBEEF: n=4 |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=-1 |
| 8 | RCX=2147516415 | 65535 | 65535 | 65535 | yes | 0x80007FFF: n=1 single word=0x7FFF=32767 -> 0 |
| 9 | RCX=9223231301513871360 | 0 | 0 | 0 | yes | 0x7FFF80007FFF8000: n=1 lower word=0x8000=-32768 |
| 10 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 single signed word |

## Source

```c
/* PC-state VM tracking running min and max of SIGNED i16 words:
 *
 *   n = (x & 3) + 1;
 *   s = x; mn = +32767; mx = -32768;
 *   while (n) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     int64_t v = (int64_t)sw;
 *     if (v > mx) mx = v;
 *     if (v < mn) mn = v;
 *     s >>= 16;
 *     n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_word_range64_loop_target.
 *
 * Distinct from:
 *   - vm_word_range64_loop          (UNSIGNED u16 cmp -> umax/umin folds)
 *   - vm_signed_byterange64_loop    (signed i8, 8-bit stride)
 *
 * Tests sext-i16 + SIGNED cmp+select reductions at word stride.
 * Per documented lifter asymmetry, signed cmp+select stays as raw
 * `icmp slt + select` (does NOT fold to llvm.smax.i64/smin.i64).
 * Uses n-decrement loop control (4 stateful slots: n,s,mn,mx).
 */
#include <stdio.h>
#include <stdint.h>

enum SwrVmPc {
    SWR_INIT_ALL = 0,
    SWR_CHECK    = 1,
    SWR_BODY     = 2,
    SWR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_signed_word_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SWR_INIT_ALL;

    while (1) {
        if (pc == SWR_INIT_ALL) {
            n  = (x & 3ull) + 1ull;
            s  = x;
            mn = 32767;
            mx = -32768;
            pc = SWR_CHECK;
        } else if (pc == SWR_CHECK) {
            pc = (n > 0ull) ? SWR_BODY : SWR_HALT;
        } else if (pc == SWR_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            int64_t v  = (int64_t)sw;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            s = s >> 16;
            n = n - 1ull;
            pc = SWR_CHECK;
        } else if (pc == SWR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_word_range64(0x80007FFF)=%llu\n",
           (unsigned long long)vm_signed_word_range64_loop_target(0x80007FFFull));
    return 0;
}
```
