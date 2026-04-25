# vm_byterev_window64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byterev_window64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byterev_window64_loop.ll`
- **Symbol:** `vm_byterev_window64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byterev_window64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byterev_window64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 256 | 256 | 256 | yes | x=1 n=2: bytes [1,0] -> 0x0100=256 |
| 3 | RCX=2 | 131072 | 131072 | 131072 | yes | x=2 n=3: bytes [2,0,0] -> 0x020000 |
| 4 | RCX=7 | 504403158265495552 | 504403158265495552 | 504403158265495552 | yes | x=7 n=8: byte 7 ends up at byte position 7 (high) of r |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: r=byte0=8 |
| 6 | RCX=3405691582 | 53685849048481792 | 53685849048481792 | 53685849048481792 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 17275436389634146304 | 17275436389634146304 | 17275436389634146304 | yes | 0xDEADBEEF: n=8 full byteswap |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | all 0xFF: n=8 palindrome |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 only byte0=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1 only byte0=0xF0 |

## Source

```c
/* PC-state VM that packs the lower n = (x & 7) + 1 bytes of x into the
 * accumulator r in REVERSED byte order:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 8) | (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byterev_window64_loop_target.
 *
 * Distinct from vm_bswap64_loop which is a fixed 8-byte byteswap (and
 * gets folded to llvm.bswap.i64).  Here the trip count is symbolic
 * (1..8), so the result is the reverse of the lowest n bytes only --
 * which the lifter cannot collapse to a single intrinsic.  Tests
 * shl-by-8 + or + lshr-by-8 chain inside a counter-bound loop body.
 *
 * Special cases worth noting:
 *   - n=1: r ends up equal to byte0 (no rotation possible)
 *   - n=8 with all 0xFF: result is the same all-0xFF input (palindrome)
 */
#include <stdio.h>
#include <stdint.h>

enum BvVmPc {
    BV_INIT_ALL = 0,
    BV_CHECK    = 1,
    BV_PACK     = 2,
    BV_SHIFT    = 3,
    BV_INC      = 4,
    BV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_byterev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BV_INIT_ALL;

    while (1) {
        if (pc == BV_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BV_CHECK;
        } else if (pc == BV_CHECK) {
            pc = (i < n) ? BV_PACK : BV_HALT;
        } else if (pc == BV_PACK) {
            r = (r << 8) | (s & 0xFFull);
            pc = BV_SHIFT;
        } else if (pc == BV_SHIFT) {
            s = s >> 8;
            pc = BV_INC;
        } else if (pc == BV_INC) {
            i = i + 1ull;
            pc = BV_CHECK;
        } else if (pc == BV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byterev_window64(0x0102030405060708)=%llu\n",
           (unsigned long long)vm_byterev_window64_loop_target(0x0102030405060708ull));
    return 0;
}
```
