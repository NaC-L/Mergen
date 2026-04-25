# vm_shiftin_top64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_shiftin_top64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_shiftin_top64_loop.ll`
- **Symbol:** `vm_shiftin_top64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_shiftin_top64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_shiftin_top64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 281474976710656 | 281474976710656 | 281474976710656 | yes | x=1 n=2: byte0=1 << 56=2^56; >>8 then OR byte1=0 << 56 |
| 3 | RCX=2 | 2199023255552 | 2199023255552 | 2199023255552 | yes | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: byte0=7 ends up at byte 0 after 8 right-shifts |
| 5 | RCX=8 | 576460752303423488 | 576460752303423488 | 576460752303423488 | yes | x=8 n=1: 8 << 56 |
| 6 | RCX=3405691582 | 871857044992 | 871857044992 | 871857044992 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 3735928559 | 3735928559 | 3735928559 | yes | 0xDEADBEEF: n=8 - all bytes traverse top->bottom; result equals input low 32 bits |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | all 0xFF n=8: palindrome invariant |
| 9 | RCX=72623859790382856 | 576460752303423488 | 576460752303423488 | 576460752303423488 | yes | 0x0102...0708: n=1 byte0=8 << 56 (matches x=8) |
| 10 | RCX=1311768467463790320 | 17293822569102704640 | 17293822569102704640 | 17293822569102704640 | yes | 0x12345...EF0: n=1 byte0=0xF0 << 56 |

## Source

```c
/* PC-state VM that builds r as a shift register fed from the top:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> 8) | ((s & 0xFF) << 56);   // shift in byte at top
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_shiftin_top64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (shl-or pack from low end)
 *   - vm_nibrev_window64_loop  (4-bit shift-or pack)
 *   - vm_byte_loop / vm_xorbytes64_loop (no shift register pattern)
 *
 * Tests `lshr i64 r, 8 | shl i64 byte, 56` shift-register update
 * pattern.  After n=8 iterations with all-FF input, r is preserved
 * (palindrome invariant); for n < 8 the upper bytes of r are filled
 * with x's lower bytes shifted into MSB position one at a time.
 */
#include <stdio.h>
#include <stdint.h>

enum StVmPc {
    ST_INIT_ALL = 0,
    ST_CHECK    = 1,
    ST_BODY     = 2,
    ST_INC      = 3,
    ST_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_shiftin_top64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ST_INIT_ALL;

    while (1) {
        if (pc == ST_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY : ST_HALT;
        } else if (pc == ST_BODY) {
            r = (r >> 8) | ((s & 0xFFull) << 56);
            s = s >> 8;
            pc = ST_INC;
        } else if (pc == ST_INC) {
            i = i + 1ull;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_shiftin_top64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_shiftin_top64_loop_target(0xDEADBEEFull));
    return 0;
}
```
