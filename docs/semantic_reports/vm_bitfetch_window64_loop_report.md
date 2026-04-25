# vm_bitfetch_window64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bitfetch_window64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bitfetch_window64_loop.ll`
- **Symbol:** `vm_bitfetch_window64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bitfetch_window64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bitfetch_window64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 2 | 2 | 2 | yes | x=1 n=2: bits [1,0] reversed -> 0b10=2 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3: bits [0,1,0] reversed -> 0b010=2 |
| 4 | RCX=7 | 224 | 224 | 224 | yes | x=7 n=8: bits 0..7 are [1,1,1,0,0,0,0,0] -> 0b11100000=224 |
| 5 | RCX=8 | 0 | 0 | 0 | yes | x=8 n=1: bit0=0 |
| 6 | RCX=3405691582 | 62 | 62 | 62 | yes | 0xCAFEBABE: n=7 low 7 bits reversed |
| 7 | RCX=3735928559 | 247 | 247 | 247 | yes | 0xDEADBEEF: n=8 low byte reversed |
| 8 | RCX=18446744073709551615 | 255 | 255 | 255 | yes | all 0xFF: n=8 low byte all 1s -> 255 |
| 9 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 bit0=0 |
| 10 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 bit0=0 |

## Source

```c
/* PC-state VM that reverses the lower n = (x & 7) + 1 bits of x by
 * shifting them in one at a time, fetching bit i with a DYNAMIC shift:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 1) | ((x >> i) & 1);   // dynamic shift amount = i
 *   }
 *   return r;
 *
 * Lift target: vm_bitfetch_window64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop  (8-bit window, fixed shift-by-8)
 *   - vm_nibrev_window64_loop   (4-bit window, fixed shift-by-4)
 *   - vm_bitreverse64_loop      (full 64-bit reverse, may fold)
 *
 * Tests `lshr i64 x, i` with i a loop-index variable - dynamic shift
 * amount inside dispatcher loop body.  Result is a bitwise reversal
 * of the low n bits of x.  Single-bit window with variable shift makes
 * the lifter handle non-constant shift counts iteration-by-iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum BfVmPc {
    BF_INIT_ALL = 0,
    BF_CHECK    = 1,
    BF_BODY     = 2,
    BF_INC      = 3,
    BF_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bitfetch_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BF_INIT_ALL;

    while (1) {
        if (pc == BF_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = BF_CHECK;
        } else if (pc == BF_CHECK) {
            pc = (i < n) ? BF_BODY : BF_HALT;
        } else if (pc == BF_BODY) {
            r = (r << 1) | ((x >> i) & 1ull);
            pc = BF_INC;
        } else if (pc == BF_INC) {
            i = i + 1ull;
            pc = BF_CHECK;
        } else if (pc == BF_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bitfetch_window64(0xFF)=%llu\n",
           (unsigned long long)vm_bitfetch_window64_loop_target(0xFFull));
    return 0;
}
```
