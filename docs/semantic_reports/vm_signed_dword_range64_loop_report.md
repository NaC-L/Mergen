# vm_signed_dword_range64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_dword_range64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signed_dword_range64_loop.ll`
- **Symbol:** `vm_signed_dword_range64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_dword_range64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_dword_range64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: dwords [+1,0] |
| 3 | RCX=3735928559 | 559038737 | 559038737 | 559038737 | yes | 0xDEADBEEF n=2: dwords [-559038737, 0] |
| 4 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=-1 |
| 5 | RCX=2147483648 | 0 | 0 | 0 | yes | x=0x80000000 n=1: only one dword |
| 6 | RCX=2147483647 | 2147483647 | 2147483647 | 2147483647 | yes | x=0x7FFFFFFF n=2: dwords [+max, 0] |
| 7 | RCX=6442450943 | 2147483646 | 2147483646 | 2147483646 | yes | 0x17FFFFFFF n=2: dwords [+max, +1] |
| 8 | RCX=9223372032559808513 | 2147483646 | 2147483646 | 2147483646 | yes | 0x7FFFFFFF00000001 n=2: dwords [+1, +max] |
| 9 | RCX=9223372041149743103 | 2147483647 | 2147483647 | 2147483647 | yes | 0x80000000FFFFFFFF n=2: dwords [-1, -2^31] |
| 10 | RCX=18446744071562067969 | 2147483646 | 2147483646 | 2147483646 | yes | 0xFFFFFFFF80000001 n=2: dwords [-max+1, -1] |

## Source

```c
/* PC-state VM tracking signed-i32 dword min/max range:
 *
 *   n = (x & 1) + 1;
 *   s = x; mn = INT32_MAX; mx = INT32_MIN;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     int64_t v  = (int64_t)sd;
 *     if (v > mx) mx = v;
 *     if (v < mn) mn = v;
 *     s >>= 32;
 *     n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_dword_range64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_range64_loop          (UNSIGNED u32 -> umax/umin folds)
 *   - vm_signed_byterange64_loop     (signed i8, 8-bit stride)
 *   - vm_signed_word_range64_loop    (signed i16, 16-bit stride)
 *
 * Completes the range coverage matrix (3 widths x 2 signs).  Per
 * documented signed-cmp asymmetry, signed cmp+select stays raw
 * `icmp slt + select` rather than folding to llvm.smax.i64/smin.i64.
 * 4 stateful slots (n,s,mn,mx) with n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum SdrVmPc {
    SDR_INIT_ALL = 0,
    SDR_CHECK    = 1,
    SDR_BODY     = 2,
    SDR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_signed_dword_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SDR_INIT_ALL;

    while (1) {
        if (pc == SDR_INIT_ALL) {
            n  = (x & 1ull) + 1ull;
            s  = x;
            mn = 2147483647;
            mx = -2147483648LL;
            pc = SDR_CHECK;
        } else if (pc == SDR_CHECK) {
            pc = (n > 0ull) ? SDR_BODY : SDR_HALT;
        } else if (pc == SDR_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            int64_t v  = (int64_t)sd;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            s = s >> 32;
            n = n - 1ull;
            pc = SDR_CHECK;
        } else if (pc == SDR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_dword_range64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_signed_dword_range64_loop_target(0xDEADBEEFull));
    return 0;
}
```
