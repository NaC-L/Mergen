# vm_bytesq_sum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytesq_sum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bytesq_sum64_loop.ll`
- **Symbol:** `vm_bytesq_sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytesq_sum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytesq_sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: 1*1 + 0=1 |
| 3 | RCX=2 | 4 | 4 | 4 | yes | x=2 n=3: 2*2=4 |
| 4 | RCX=7 | 49 | 49 | 49 | yes | x=7 n=8: only byte0=7 -> 49 |
| 5 | RCX=8 | 64 | 64 | 64 | yes | x=8 n=1: 8*8=64 |
| 6 | RCX=3405691582 | 176016 | 176016 | 176016 | yes | 0xCAFEBABE: n=7 sum of squared bytes |
| 7 | RCX=3735928559 | 172434 | 172434 | 172434 | yes | 0xDEADBEEF: n=8 sum of squared bytes |
| 8 | RCX=18446744073709551615 | 520200 | 520200 | 520200 | yes | all 0xFF n=8: 8*255*255=520200 |
| 9 | RCX=72623859790382856 | 64 | 64 | 64 | yes | 0x0102...0708: n=1 byte0=8 -> 64 |
| 10 | RCX=1311768467463790320 | 57600 | 57600 | 57600 | yes | 0x12345...EF0: n=1 byte0=0xF0=240 -> 57600 |

## Source

```c
/* PC-state VM that sums squared bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r + b * b;          // u8 squared
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytesq_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_popsq64_loop           (sum of squared POPCOUNTS of bytes)
 *   - vm_squareadd64_loop       (single-state r = r*r + i quadratic)
 *   - vm_uintadd_byte_idx64_loop (byte * counter)
 *
 * Tests u8 self-multiply (b * b) accumulator across a byte stream.
 * No counter scaling; every byte squared and summed.  All-0xFF input
 * accumulates 8 * 255*255 = 8 * 65025 = 520200.
 */
#include <stdio.h>
#include <stdint.h>

enum BqVmPc {
    BQ_INIT_ALL = 0,
    BQ_CHECK    = 1,
    BQ_BODY     = 2,
    BQ_INC      = 3,
    BQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytesq_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BQ_INIT_ALL;

    while (1) {
        if (pc == BQ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_CHECK) {
            pc = (i < n) ? BQ_BODY : BQ_HALT;
        } else if (pc == BQ_BODY) {
            uint64_t b = s & 0xFFull;
            r = r + b * b;
            s = s >> 8;
            pc = BQ_INC;
        } else if (pc == BQ_INC) {
            i = i + 1ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytesq_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_bytesq_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
```
