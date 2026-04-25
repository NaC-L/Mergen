# vm_dword_range64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dword_range64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dword_range64_loop.ll`
- **Symbol:** `vm_dword_range64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dword_range64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dword_range64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: dwords [1,0] |
| 3 | RCX=2 | 0 | 0 | 0 | yes | x=2 n=1 single dword |
| 4 | RCX=3 | 3 | 3 | 3 | yes | x=3 n=2: dwords [3,0] |
| 5 | RCX=3405691582 | 0 | 0 | 0 | yes | 0xCAFEBABE: n=1 single dword |
| 6 | RCX=3735928559 | 3735928559 | 3735928559 | 3735928559 | yes | 0xDEADBEEF: n=2 dwords [0xDEADBEEF,0] |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=0xFFFFFFFF |
| 8 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 single dword |
| 9 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 single dword |
| 10 | RCX=18364758544493064720 | 0 | 0 | 0 | yes | 0xFEDCBA9876543210: n=1 single dword |

## Source

```c
/* PC-state VM tracking u32 dword min/max range over n=(x&1)+1 iters:
 *
 *   n = (x & 1) + 1;
 *   s = x; mn = 0xFFFFFFFF; mx = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     if (d > mx) mx = d;
 *     if (d < mn) mn = d;
 *     s >>= 32;
 *     n--;
 *   }
 *   return mx - mn;
 *
 * Lift target: vm_dword_range64_loop_target.
 *
 * Distinct from:
 *   - vm_byterange64_loop  (u8 byte stride)
 *   - vm_word_range64_loop (u16 word stride)
 *
 * Tests umax/umin folds at 32-bit dword stride.  Single-dword inputs
 * always return 0 (mx=mn=dword).  4 stateful slots (n,s,mn,mx) with
 * n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum DrVmPc {
    DR_INIT_ALL = 0,
    DR_CHECK    = 1,
    DR_BODY     = 2,
    DR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = DR_INIT_ALL;

    while (1) {
        if (pc == DR_INIT_ALL) {
            n  = (x & 1ull) + 1ull;
            s  = x;
            mn = 0xFFFFFFFFull;
            mx = 0ull;
            pc = DR_CHECK;
        } else if (pc == DR_CHECK) {
            pc = (n > 0ull) ? DR_BODY : DR_HALT;
        } else if (pc == DR_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            mx = (d > mx) ? d : mx;
            mn = (d < mn) ? d : mn;
            s = s >> 32;
            n = n - 1ull;
            pc = DR_CHECK;
        } else if (pc == DR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_range64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dword_range64_loop_target(0xDEADBEEFull));
    return 0;
}
```
