# vm_xor_shifted_self_byte64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xor_shifted_self_byte64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xor_shifted_self_byte64_loop.ll`
- **Symbol:** `vm_xor_shifted_self_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xor_shifted_self_byte64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xor_shifted_self_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 72339069014638593 | 72339069014638593 | 72339069014638593 | yes | x=1 n=2 |
| 3 | RCX=2 | 144117387099111426 | 144117387099111426 | 144117387099111426 | yes | x=2 n=3 |
| 4 | RCX=7 | 506381209866536704 | 506381209866536704 | 506381209866536704 | yes | x=7 n=8 |
| 5 | RCX=8 | 576460752303423496 | 576460752303423496 | 576460752303423496 | yes | x=8 n=1 |
| 6 | RCX=3405691582 | 3490418122958975024 | 3490418122958975024 | 3490418122958975024 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 2468625636935069440 | 2468625636935069440 | 2468625636935069440 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709551360 | 18446744073709551360 | 18446744073709551360 | yes | all 0xFF: cascading XOR mask propagates |
| 9 | RCX=72623859790382856 | 649363900864856335 | 649363900864856335 | 649363900864856335 | yes | 0x0102...0708: n=1 |
| 10 | RCX=1311768467463790320 | 16295820255188902446 | 16295820255188902446 | 16295820255188902446 | yes | 0x12345...EF0: n=1 |

## Source

```c
/* PC-state VM with self-shift XOR cross-feeding the byte stream:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((r >> 8) | ((s & 0xFF) << 56));
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xor_shifted_self_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_shiftin_top64_loop      (assigns (r>>8)|(byte<<56), no XOR)
 *   - vm_xormulself_byte64_loop  (mul-self with byte, not shift-self)
 *   - vm_byterev_window64_loop   (shift register filling, no XOR)
 *
 * Tests `r XOR (r>>8 OR byte<<56)` - self-shift used as XOR mask
 * combined with byte injected at MSB position.  Each iter mixes
 * the running r with its lower 56 bits and a byte at the top.
 */
#include <stdio.h>
#include <stdint.h>

enum XsVmPc {
    XS_INIT_ALL = 0,
    XS_CHECK    = 1,
    XS_BODY     = 2,
    XS_INC      = 3,
    XS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xor_shifted_self_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XS_INIT_ALL;

    while (1) {
        if (pc == XS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = XS_CHECK;
        } else if (pc == XS_CHECK) {
            pc = (i < n) ? XS_BODY : XS_HALT;
        } else if (pc == XS_BODY) {
            r = r ^ ((r >> 8) | ((s & 0xFFull) << 56));
            s = s >> 8;
            pc = XS_INC;
        } else if (pc == XS_INC) {
            i = i + 1ull;
            pc = XS_CHECK;
        } else if (pc == XS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xor_shifted_self_byte64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_xor_shifted_self_byte64_loop_target(0xDEADBEEFull));
    return 0;
}
```
