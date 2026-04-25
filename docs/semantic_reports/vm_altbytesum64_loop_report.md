# vm_altbytesum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_altbytesum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_altbytesum64_loop.ll`
- **Symbol:** `vm_altbytesum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_altbytesum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_altbytesum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero bytes |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: +1 |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF: +255 |
| 4 | RCX=72623859790382856 | 4 | 4 | 4 | yes | 0x0102030405060708: 8-(7-(6-(5-(4-(3-(2-1))))))=4 |
| 5 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: 8 bytes alternating cancel to 0 |
| 6 | RCX=128 | 128 | 128 | 128 | yes | x=0x80: +128 (positive byte) |
| 7 | RCX=9259542123273814144 | 128 | 128 | 128 | yes | 0x8080808080808080: +/- 128 cancels to +128 |
| 8 | RCX=3405691582 | 56 | 56 | 56 | yes | 0xCAFEBABE: 4-byte alternating sum |
| 9 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x123456789ABCDEF0 |
| 10 | RCX=16045690985374415566 | 18446744073709551555 | 18446744073709551555 | 18446744073709551555 | yes | 0xDEADBEEFFEEDFACE: result negative -> u64=2^64-61 |

## Source

```c
/* PC-state VM that computes an alternating-sign byte sum:
 *   r = +b0 - b1 + b2 - b3 + ... over n = (x & 15) + 1 bytes
 * with r kept as a signed i64 accumulator and returned as u64.
 *
 *   n = (x & 15) + 1;
 *   s = x; r = 0; sign = 1;
 *   while (n) {
 *     r += sign * (s & 0xFF);
 *     s >>= 8;
 *     sign = -sign;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_altbytesum64_loop_target.
 *
 * Distinct from vm_xorbytes64 (XOR of bytes) and vm_byteparity64 (1-bit
 * parity).  Tests: signed accumulator, sign flip per iteration via
 * negation, and signed-times-unsigned multiply.  Produces negative
 * (i64) values for inputs where the odd-indexed bytes dominate.
 */
#include <stdio.h>
#include <stdint.h>

enum AbVmPc {
    AB_LOAD_N    = 0,
    AB_INIT_REGS = 1,
    AB_CHECK     = 2,
    AB_ACC       = 3,
    AB_SHIFT     = 4,
    AB_FLIP      = 5,
    AB_DEC       = 6,
    AB_HALT      = 7,
};

__declspec(noinline)
uint64_t vm_altbytesum64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    int64_t  r    = 0;
    int64_t  sign = 1;
    int      pc   = AB_LOAD_N;

    while (1) {
        if (pc == AB_LOAD_N) {
            n = (x & 15ull) + 1ull;
            pc = AB_INIT_REGS;
        } else if (pc == AB_INIT_REGS) {
            s    = x;
            r    = 0;
            sign = 1;
            pc = AB_CHECK;
        } else if (pc == AB_CHECK) {
            pc = (n > 0ull) ? AB_ACC : AB_HALT;
        } else if (pc == AB_ACC) {
            r = r + sign * (int64_t)(s & 0xFFull);
            pc = AB_SHIFT;
        } else if (pc == AB_SHIFT) {
            s = s >> 8;
            pc = AB_FLIP;
        } else if (pc == AB_FLIP) {
            sign = -sign;
            pc = AB_DEC;
        } else if (pc == AB_DEC) {
            n = n - 1ull;
            pc = AB_CHECK;
        } else if (pc == AB_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_altbytesum64(0x0102030405060708)=%llu\n",
           (unsigned long long)vm_altbytesum64_loop_target(0x0102030405060708ull));
    return 0;
}
```
