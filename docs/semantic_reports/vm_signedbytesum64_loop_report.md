# vm_signedbytesum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_signedbytesum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_signedbytesum64_loop.ll`
- **Symbol:** `vm_signedbytesum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_signedbytesum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_signedbytesum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero bytes |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: sext(1)=+1 |
| 3 | RCX=255 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | x=0xFF: sext(0xFF)=-1 |
| 4 | RCX=128 | 18446744073709551488 | 18446744073709551488 | 18446744073709551488 | yes | x=0x80: sext(0x80)=-128 |
| 5 | RCX=9259542123273814144 | 18446744073709551488 | 18446744073709551488 | 18446744073709551488 | yes | 0x80*8: -128*1=-128 (n=1) |
| 6 | RCX=9187201950435737471 | 1016 | 1016 | 1016 | yes | 0x7F*8: +127*8=1016 (n=8) |
| 7 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102030405060708: 8+7+...+1=36? n=(8&7)+1=1: just byte0=8 |
| 8 | RCX=3405691582 | 18446744073709551424 | 18446744073709551424 | 18446744073709551424 | yes | 0xCAFEBABE: n=(0xBE&7)+1=7 |
| 9 | RCX=16045690985374415566 | 18446744073709551373 | 18446744073709551373 | 18446744073709551373 | yes | 0xDEADBEEFFEEDFACE: n=7 |
| 10 | RCX=18446744073709551615 | 18446744073709551608 | 18446744073709551608 | 18446744073709551608 | yes | all 0xFF: -1*8=-8 |

## Source

```c
/* PC-state VM that sums bytes interpreted as signed int8_t into an i64
 * accumulator over n = (x & 7) + 1 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);   // sext i8 -> i64
 *     r += (int64_t)sb;
 *     s >>= 8;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signedbytesum64_loop_target.
 *
 * Distinct from vm_altbytesum64_loop (fixed alternating sign per
 * iteration): here every byte is sign-extended individually, so the
 * sign of each contribution is data-dependent on each byte's high bit.
 * Exercises i8 sext (not the i8 zext + neg pattern).  Bytes 0x00..0x7F
 * contribute +0..+127, bytes 0x80..0xFF contribute -128..-1.  Many
 * inputs produce negative i64 results that round-trip through u64.
 */
#include <stdio.h>
#include <stdint.h>

enum SbVmPc {
    SB_LOAD_N    = 0,
    SB_INIT_REGS = 1,
    SB_CHECK     = 2,
    SB_ACC       = 3,
    SB_SHIFT     = 4,
    SB_DEC       = 5,
    SB_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_signedbytesum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    int      pc = SB_LOAD_N;

    while (1) {
        if (pc == SB_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = SB_INIT_REGS;
        } else if (pc == SB_INIT_REGS) {
            s = x;
            r = 0;
            pc = SB_CHECK;
        } else if (pc == SB_CHECK) {
            pc = (n > 0ull) ? SB_ACC : SB_HALT;
        } else if (pc == SB_ACC) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r + (int64_t)sb;
            pc = SB_SHIFT;
        } else if (pc == SB_SHIFT) {
            s = s >> 8;
            pc = SB_DEC;
        } else if (pc == SB_DEC) {
            n = n - 1ull;
            pc = SB_CHECK;
        } else if (pc == SB_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_sgnbytesum64(0x7F7F7F7F7F7F7F7F)=%llu\n",
           (unsigned long long)vm_signedbytesum64_loop_target(0x7F7F7F7F7F7F7F7Full));
    return 0;
}
```
