# vm_byterange64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byterange64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byterange64_loop.ll`
- **Symbol:** `vm_byterange64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byterange64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byterange64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero bytes -> mx=mn=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: n=(1&7)+1=2: bytes [1,0] -> mx=1 mn=0 |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF: n=8: byte0=255 rest=0 |
| 4 | RCX=128 | 0 | 0 | 0 | yes | x=0x80: n=1: only byte0=0x80 |
| 5 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1: only byte0=8 |
| 6 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1: only byte0=0xF0 |
| 7 | RCX=3405691582 | 254 | 254 | 254 | yes | 0xCAFEBABE: n=7: max=0xFE min=0 |
| 8 | RCX=16045690985374415566 | 81 | 81 | 81 | yes | 0xDEADBEEFFEEDFACE: n=7: range across non-zero bytes |
| 9 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: mx=mn=255 |
| 10 | RCX=9187201950435737471 | 0 | 0 | 0 | yes | 0x7F*8: mx=mn=127 |

## Source

```c
/* PC-state VM that tracks the running min and max bytes across the
 * lower n = (x & 7) + 1 bytes and returns (max - min):
 *
 *   n = (x & 7) + 1;
 *   s = x; mn = 0xFF; mx = 0;
 *   while (n) {
 *     b = s & 0xFF;
 *     if (b > mx) mx = b;
 *     if (b < mn) mn = b;
 *     s >>= 8; n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_byterange64_loop_target.
 *
 * Distinct from vm_bytemax64_loop (single-reduction max only): runs
 * TWO independent cmp-driven reductions in lock-step inside the same
 * loop body, each updating its own slot, plus a final subtract.  The
 * lifter is expected to fold both branches into llvm.umax.i64 and
 * llvm.umin.i64 and then sub the final values.
 *
 * Single-byte inputs always return 0 (byte = mx = mn).
 */
#include <stdio.h>
#include <stdint.h>

enum BrVmPc {
    BR_LOAD_N    = 0,
    BR_INIT_REGS = 1,
    BR_CHECK     = 2,
    BR_BODY      = 3,
    BR_SHIFT     = 4,
    BR_DEC       = 5,
    BR_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_byterange64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = BR_LOAD_N;

    while (1) {
        if (pc == BR_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = BR_INIT_REGS;
        } else if (pc == BR_INIT_REGS) {
            s  = x;
            mn = 0xFFull;
            mx = 0ull;
            pc = BR_CHECK;
        } else if (pc == BR_CHECK) {
            pc = (n > 0ull) ? BR_BODY : BR_HALT;
        } else if (pc == BR_BODY) {
            uint64_t b = s & 0xFFull;
            mx = (b > mx) ? b : mx;
            mn = (b < mn) ? b : mn;
            pc = BR_SHIFT;
        } else if (pc == BR_SHIFT) {
            s = s >> 8;
            pc = BR_DEC;
        } else if (pc == BR_DEC) {
            n = n - 1ull;
            pc = BR_CHECK;
        } else if (pc == BR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byterange64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byterange64_loop_target(0xCAFEBABEull));
    return 0;
}
```
