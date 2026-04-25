# vm_signed_dword_sum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_dword_sum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signed_dword_sum64_loop.ll`
- **Symbol:** `vm_signed_dword_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_dword_sum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_dword_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: dword=1 +0 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=1: dword=2 |
| 4 | RCX=3 | 3 | 3 | 3 | yes | x=3 n=2 |
| 5 | RCX=3405691582 | 18446744072820275902 | 18446744072820275902 | 18446744072820275902 | yes | 0xCAFEBABE: n=1 dword high bit set, sext negative -> 2^64-magnitude |
| 6 | RCX=3735928559 | 18446744073150512879 | 18446744073150512879 | 18446744073150512879 | yes | 0xDEADBEEF: n=2 negative + zero |
| 7 | RCX=18446744073709551615 | 18446744073709551614 | 18446744073709551614 | 18446744073709551614 | yes | all 0xFF: 2 sext(-1) sums = -2 -> 2^64-2 |
| 8 | RCX=2147483648 | 18446744071562067968 | 18446744071562067968 | 18446744071562067968 | yes | x=2^31 (most negative i32) n=1: -2^31 |
| 9 | RCX=9223372034707292160 | 18446744071562067968 | 18446744071562067968 | 18446744071562067968 | yes | 0x7FFFFFFF80000000: n=1 lower=0x80000000=-2^31 |
| 10 | RCX=1311768467463790320 | 18446744072010653424 | 18446744072010653424 | 18446744072010653424 | yes | 0x12345...EF0: n=1 lower dword high bit set |

## Source

```c
/* PC-state VM that sums sext-i32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     r = r + (int64_t)sd;     // sext i32 -> i64
 *     s >>= 32;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signed_dword_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop  (sext-i8 byte sum, 8-bit stride)
 *   - vm_dword_xormul64_loop   (zext-i32 dword XOR, no sign extension)
 *
 * Tests `sext i32 to i64` per iteration on a 32-bit dword stream
 * (high bit of dword sign-extends).  Negative-dword inputs land
 * near 2^64 - magnitude in the sum.
 */
#include <stdio.h>
#include <stdint.h>

enum SdVmPc {
    SD_INIT_ALL = 0,
    SD_CHECK    = 1,
    SD_BODY     = 2,
    SD_INC      = 3,
    SD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signed_dword_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = SD_INIT_ALL;

    while (1) {
        if (pc == SD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = SD_CHECK;
        } else if (pc == SD_CHECK) {
            pc = (i < n) ? SD_BODY : SD_HALT;
        } else if (pc == SD_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            r = r + (int64_t)sd;
            s = s >> 32;
            pc = SD_INC;
        } else if (pc == SD_INC) {
            i = i + 1ull;
            pc = SD_CHECK;
        } else if (pc == SD_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_dword_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signed_dword_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
