# vm_nibrev_window64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_nibrev_window64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_nibrev_window64_loop.ll`
- **Symbol:** `vm_nibrev_window64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_nibrev_window64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_nibrev_window64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero |
| 2 | RCX=1 | 16 | 16 | 16 | yes | x=1 n=2: nibbles [1,0] -> 0x10 |
| 3 | RCX=2 | 512 | 512 | 512 | yes | x=2 n=3: nibbles [2,0,0] -> 0x200 |
| 4 | RCX=7 | 1879048192 | 1879048192 | 1879048192 | yes | x=7 n=8: nibble 7 ends up at high pos -> 0x70000000 |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: r=low nibble=8 |
| 6 | RCX=3405691582 | 247119610 | 247119610 | 247119610 | yes | 0xCAFEBABE: n=7 nibble-rev of low 28 bits |
| 7 | RCX=3735928559 | 4276869869 | 4276869869 | 4276869869 | yes | 0xDEADBEEF: n=8 full 32-bit nibble reverse |
| 8 | RCX=18446744073709551615 | 4294967295 | 4294967295 | 4294967295 | yes | all 0xFF: n=8 -> 0xFFFFFFFF (8 nibbles of 0xF) |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 low nibble=8 (matches x=8) |
| 10 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 low nibble=0 |

## Source

```c
/* PC-state VM that reverses the lower n = (x & 7) + 1 NIBBLES of x:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 4) | (s & 0xF);
 *     s >>= 4;
 *   }
 *   return r;
 *
 * Lift target: vm_nibrev_window64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (8-bit window, shl/lshr by 8)
 *   - vm_nibrev64_loop         (full fixed 16-nibble reverse, may fold)
 *
 * Tests shl-by-4 + or + lshr-by-4 chain inside a counter-bound loop.
 * Trip count maxes at 8, so even with n=8 only the lower 32 bits of
 * x are consumed -- the upper half of x is irrelevant to the result.
 * Single-trip cases (n=1) reduce to the low nibble of x.
 */
#include <stdio.h>
#include <stdint.h>

enum NwVmPc {
    NW_INIT_ALL = 0,
    NW_CHECK    = 1,
    NW_PACK     = 2,
    NW_SHIFT    = 3,
    NW_INC      = 4,
    NW_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_nibrev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NW_INIT_ALL;

    while (1) {
        if (pc == NW_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = NW_CHECK;
        } else if (pc == NW_CHECK) {
            pc = (i < n) ? NW_PACK : NW_HALT;
        } else if (pc == NW_PACK) {
            r = (r << 4) | (s & 0xFull);
            pc = NW_SHIFT;
        } else if (pc == NW_SHIFT) {
            s = s >> 4;
            pc = NW_INC;
        } else if (pc == NW_INC) {
            i = i + 1ull;
            pc = NW_CHECK;
        } else if (pc == NW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nibrev_window64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_nibrev_window64_loop_target(0xDEADBEEFull));
    return 0;
}
```
