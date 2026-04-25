# vm_signed_byterange64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signed_byterange64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signed_byterange64_loop.ll`
- **Symbol:** `vm_signed_byterange64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signed_byterange64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signed_byterange64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero bytes -> mx=mn=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: bytes [+1,0] -> range=1 |
| 3 | RCX=255 | 1 | 1 | 1 | yes | x=0xFF: bytes [-1,0,0,0,0,0,0,0] -> 0-(-1)=1 |
| 4 | RCX=128 | 0 | 0 | 0 | yes | x=0x80: n=1, only sext(0x80)=-128 |
| 5 | RCX=9259260644002070655 | 255 | 255 | 255 | yes | 0x807F807F807F807F: n=8, +127/-128 alternating -> max range |
| 6 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1, only byte0=+8 |
| 7 | RCX=3405691582 | 70 | 70 | 70 | yes | 0xCAFEBABE: n=7 mixed signs |
| 8 | RCX=16045690985374415566 | 81 | 81 | 81 | yes | 0xDEADBEEFFEEDFACE: n=7 all negative bytes |
| 9 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=-1 |
| 10 | RCX=9187201950435737471 | 0 | 0 | 0 | yes | 0x7F*8: mx=mn=+127 |

## Source

```c
/* PC-state VM that tracks the running min and max of bytes interpreted
 * as SIGNED int8_t across the lower n = (x & 7) + 1 bytes, then
 * returns (smax - smin) as a u64.
 *
 *   n = (x & 7) + 1;
 *   s = x; mn = +127; mx = -128;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     if ((int64_t)sb > mx) mx = sb;
 *     if ((int64_t)sb < mn) mn = sb;
 *     s >>= 8; n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_byterange64_loop_target.
 *
 * Distinct from vm_byterange64_loop (UNSIGNED min/max -> umax/umin
 * intrinsics).  Here every byte is sext (int8_t), so 0x80..0xFF fold
 * into negative i64 and the reductions should fold to llvm.smax.i64
 * and llvm.smin.i64.  Worst-case range is 255 (-128 .. +127).
 */
#include <stdio.h>
#include <stdint.h>

enum SrVmPc {
    SR_LOAD_N    = 0,
    SR_INIT_REGS = 1,
    SR_CHECK     = 2,
    SR_BODY      = 3,
    SR_SHIFT     = 4,
    SR_DEC       = 5,
    SR_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_signed_byterange64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SR_LOAD_N;

    while (1) {
        if (pc == SR_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = SR_INIT_REGS;
        } else if (pc == SR_INIT_REGS) {
            s  = x;
            mn = 127;
            mx = -128;
            pc = SR_CHECK;
        } else if (pc == SR_CHECK) {
            pc = (n > 0ull) ? SR_BODY : SR_HALT;
        } else if (pc == SR_BODY) {
            int8_t  sb = (int8_t)(s & 0xFFull);
            int64_t v  = (int64_t)sb;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            pc = SR_SHIFT;
        } else if (pc == SR_SHIFT) {
            s = s >> 8;
            pc = SR_DEC;
        } else if (pc == SR_DEC) {
            n = n - 1ull;
            pc = SR_CHECK;
        } else if (pc == SR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_sgn_byterange64(0x807F807F807F807F)=%llu\n",
           (unsigned long long)vm_signed_byterange64_loop_target(0x807F807F807F807Full));
    return 0;
}
```
