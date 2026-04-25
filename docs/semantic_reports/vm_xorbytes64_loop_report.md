# vm_xorbytes64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xorbytes64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xorbytes64_loop.ll`
- **Symbol:** `vm_xorbytes64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xorbytes64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xorbytes64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: only low byte |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF: low byte = 0xFF |
| 4 | RCX=51966 | 52 | 52 | 52 | yes | x=0xCAFE: 0xFE^0xCA=0x34 |
| 5 | RCX=3405691582 | 48 | 48 | 48 | yes | 0xCAFEBABE |
| 6 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x123456789ABCDEF0: bytes XOR cancel |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | max u64: 8x0xFF cancel |
| 8 | RCX=11400714819323198485 | 53 | 53 | 53 | yes | K (golden) |
| 9 | RCX=170 | 170 | 170 | 170 | yes | x=0xAA: only low byte |
| 10 | RCX=71777214294589695 | 0 | 0 | 0 | yes | 0x00FF00FF00FF00FF: 4x0xFF cancel |

## Source

```c
/* PC-state VM that XOR-folds all 8 bytes of x into a single byte.
 *   result = 0;
 *   for i in 0..8: result ^= (x >> (i*8)) & 0xFF;
 *   return result;     // only low 8 bits non-zero
 * 8-trip fixed loop with byte-walking shift (loop-counter * 8).
 * Lift target: vm_xorbytes64_loop_target.
 *
 * Distinct from vm_djb264_loop (multiplicative byte hash) and
 * vm_morton64_loop (1-bit fan-out spread): exercises an XOR-reduction
 * over byte slices with no multiplication.  Even-byte-count duplicates
 * cancel to zero; result is a single-byte XOR signature.
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_LOAD       = 0,
    XB_INIT       = 1,
    XB_LOOP_CHECK = 2,
    XB_LOOP_BODY  = 3,
    XB_LOOP_INC   = 4,
    XB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorbytes64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = XB_LOAD;

    while (1) {
        if (pc == XB_LOAD) {
            xx     = x;
            result = 0ull;
            pc = XB_INIT;
        } else if (pc == XB_INIT) {
            idx = 0;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_LOOP_CHECK) {
            pc = (idx < 8) ? XB_LOOP_BODY : XB_HALT;
        } else if (pc == XB_LOOP_BODY) {
            result = result ^ ((xx >> (idx * 8)) & 0xFFull);
            pc = XB_LOOP_INC;
        } else if (pc == XB_LOOP_INC) {
            idx = idx + 1;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorbytes64(0xCAFEBABE)=%llu vm_xorbytes64(0x9E3779B97F4A7C15)=%llu\n",
           (unsigned long long)vm_xorbytes64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_xorbytes64_loop_target(0x9E3779B97F4A7C15ull));
    return 0;
}
```
