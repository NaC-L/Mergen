# vm_zigzag_step64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_zigzag_step64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_zigzag_step64_loop.ll`
- **Symbol:** `vm_zigzag_step64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_zigzag_step64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_zigzag_step64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 n=1: zigzag(0)=0, then s steps but loop ends |
| 2 | RCX=1 | 14092058508772706261 | 14092058508772706261 | 14092058508772706261 | yes | x=1 n=2 |
| 3 | RCX=2 | 4354685564936845357 | 4354685564936845357 | 4354685564936845357 | yes | x=2 n=3 |
| 4 | RCX=7 | 16390740445785211241 | 16390740445785211241 | 16390740445785211241 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 16 | 16 | 16 | yes | x=8 n=1: zigzag(8)=16 (positive doubled) |
| 6 | RCX=9223372036854775808 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | x=2^63 n=1: zigzag(2^63)=2^64-1 (most negative) |
| 7 | RCX=3405691582 | 4354685571748228515 | 4354685571748228515 | 4354685571748228515 | yes | 0xCAFEBABE: n=7 |
| 8 | RCX=16045690985374415566 | 11212795369531457850 | 11212795369531457850 | 11212795369531457850 | yes | 0xDEADBEEFFEEDFACE: n=7 high-bit set initial |
| 9 | RCX=18446744073709551615 | 16390740445785211212 | 16390740445785211212 | 16390740445785211212 | yes | all 0xFF: n=8 zigzag(-1)=1 first iter |
| 10 | RCX=72623859790382856 | 145247719580765712 | 145247719580765712 | 145247719580765712 | yes | 0x0102...0708: n=1 zigzag(positive)=2x |

## Source

```c
/* PC-state VM running ZigZag encoding chained over a stepped state:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     // ZigZag: (s << 1) ^ (s as i64 >> 63)
 *     enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
 *     r = r + enc;
 *     s = s + 0x9E3779B97F4A7C15;     // golden-ratio additive step
 *   }
 *   return r;
 *
 * Lift target: vm_zigzag_step64_loop_target.
 *
 * Distinct from:
 *   - vm_splitmix64_loop (xor-mul-xor-mul-xor finalizer)
 *   - vm_xorrot64_loop   (xor + LCG mul step)
 *   - vm_signedbytesum64_loop (per-byte sext-i8)
 *
 * Tests ashr i64 ... 63 (arithmetic right shift to broadcast the sign
 * bit) inside a counter-bound loop body.  The sign-broadcast XOR with
 * shifted s implements ZigZag encoding of a signed i64; the result is
 * accumulated and the state advances by the golden-ratio additive
 * constant each iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum ZzVmPc {
    ZZ_INIT_ALL = 0,
    ZZ_CHECK    = 1,
    ZZ_BODY     = 2,
    ZZ_INC      = 3,
    ZZ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_zigzag_step64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ZZ_INIT_ALL;

    while (1) {
        if (pc == ZZ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ZZ_CHECK;
        } else if (pc == ZZ_CHECK) {
            pc = (i < n) ? ZZ_BODY : ZZ_HALT;
        } else if (pc == ZZ_BODY) {
            uint64_t enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
            r = r + enc;
            s = s + 0x9E3779B97F4A7C15ull;
            pc = ZZ_INC;
        } else if (pc == ZZ_INC) {
            i = i + 1ull;
            pc = ZZ_CHECK;
        } else if (pc == ZZ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_zigzag_step64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_zigzag_step64_loop_target(0xCAFEBABEull));
    return 0;
}
```
