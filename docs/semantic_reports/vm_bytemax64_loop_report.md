# vm_bytemax64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytemax64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bytemax64_loop.ll`
- **Symbol:** `vm_bytemax64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytemax64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytemax64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero bytes |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: max byte=1 |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF: max byte=255 |
| 4 | RCX=128 | 128 | 128 | 128 | yes | x=0x80: max byte=128 |
| 5 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=(8&7)+1=1: only byte0=8 visible |
| 6 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1: byte0=0xF0 |
| 7 | RCX=3405691582 | 254 | 254 | 254 | yes | 0xCAFEBABE: n=7: max=0xFE |
| 8 | RCX=16045690985374415566 | 254 | 254 | 254 | yes | 0xDEADBEEFFEEDFACE: n=7 |
| 9 | RCX=18446744073709551615 | 255 | 255 | 255 | yes | all 0xFF: max=255 |
| 10 | RCX=65280 | 0 | 0 | 0 | yes | 0xFF00: n=1: byte0=0 |

## Source

```c
/* PC-state VM that finds the maximum byte value across the lower n bytes
 * of x where n = (x & 7) + 1.  Pure unsigned compare-driven max-update.
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint8_t b = s & 0xFF;
 *     if (b > r) r = b;
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bytemax64_loop_target.
 *
 * Distinct from:
 *   - vm_choosemax64_loop (per-iter chooses between two locally-computed
 *     options s*3+i vs s+i*i over full u64 state)
 *   - vm_smax64_loop (signed max of a derived sequence)
 *   - vm_minarray_loop (i32 min over a stack array)
 *   - vm_bytematch64 (matches a key, doesn't track a max)
 *
 * Tests u8 cmp + select-style update where the "no-update" path keeps
 * the running max unchanged.  Bytes 0x00 are special: they NEVER
 * exceed the running max, so the lifter must keep the conditional
 * write under control.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_LOAD_N    = 0,
    BM_INIT_REGS = 1,
    BM_CHECK     = 2,
    BM_BODY      = 3,
    BM_SHIFT     = 4,
    BM_DEC       = 5,
    BM_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_bytemax64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BM_LOAD_N;

    while (1) {
        if (pc == BM_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = BM_INIT_REGS;
        } else if (pc == BM_INIT_REGS) {
            s = x;
            r = 0ull;
            pc = BM_CHECK;
        } else if (pc == BM_CHECK) {
            pc = (n > 0ull) ? BM_BODY : BM_HALT;
        } else if (pc == BM_BODY) {
            uint64_t b = s & 0xFFull;
            r = (b > r) ? b : r;
            pc = BM_SHIFT;
        } else if (pc == BM_SHIFT) {
            s = s >> 8;
            pc = BM_DEC;
        } else if (pc == BM_DEC) {
            n = n - 1ull;
            pc = BM_CHECK;
        } else if (pc == BM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytemax64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_bytemax64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
```
