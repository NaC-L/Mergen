# vm_popsq64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_popsq64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_popsq64_loop.ll`
- **Symbol:** `vm_popsq64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_popsq64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_popsq64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: low byte popcount=1, 1^2=1 |
| 3 | RCX=255 | 64 | 64 | 64 | yes | x=0xFF: 8^2=64 |
| 4 | RCX=51966 | 65 | 65 | 65 | yes | x=0xCAFE |
| 5 | RCX=72623859790382856 | 25 | 25 | 25 | yes | 0x0102030405060708 |
| 6 | RCX=14627333968688430831 | 272 | 272 | 272 | yes | 0xCAFEBABEDEADBEEF |
| 7 | RCX=18446744073709551615 | 512 | 512 | 512 | yes | max u64: 8 bytes * 64 |
| 8 | RCX=11400714819323198485 | 192 | 192 | 192 | yes | K (golden) |
| 9 | RCX=81985529216486895 | 152 | 152 | 152 | yes | 0x0123456789ABCDEF |
| 10 | RCX=3405691582 | 126 | 126 | 126 | yes | 0xCAFEBABE |

## Source

```c
/* PC-state VM that computes the sum of SQUARED per-byte popcounts.
 *   total = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF;
 *     pop = popcount8(byte);          // 0..8 via Brian Kernighan
 *     total += pop * pop;
 *   return total;
 * Outer 8-trip fixed loop containing an INNER variable-trip popcount.
 * Lift target: vm_popsq64_loop_target.
 *
 * Distinct from vm_popcount64_loop (single popcount over whole i64) and
 * vm_byteparity64_loop (1-bit reduction per byte): per-byte popcount
 * (full 0..8 count) followed by squaring then summing.  Inner loop is
 * data-dependent, outer is fixed - tests outer-fixed/inner-variable
 * nested-loop shape.
 */
#include <stdio.h>
#include <stdint.h>

enum PsVmPc {
    PS_LOAD       = 0,
    PS_OUTER_INIT = 1,
    PS_OUTER_CHK  = 2,
    PS_INNER_INIT = 3,
    PS_INNER_CHK  = 4,
    PS_INNER_BODY = 5,
    PS_OUTER_BODY = 6,
    PS_OUTER_INC  = 7,
    PS_HALT       = 8,
};

__declspec(noinline)
int vm_popsq64_loop_target(uint64_t x) {
    int      i     = 0;
    uint64_t xx    = 0;
    uint64_t b     = 0;
    int      pop   = 0;
    int      total = 0;
    int      pc    = PS_LOAD;

    while (1) {
        if (pc == PS_LOAD) {
            xx    = x;
            total = 0;
            pc = PS_OUTER_INIT;
        } else if (pc == PS_OUTER_INIT) {
            i = 0;
            pc = PS_OUTER_CHK;
        } else if (pc == PS_OUTER_CHK) {
            pc = (i < 8) ? PS_INNER_INIT : PS_HALT;
        } else if (pc == PS_INNER_INIT) {
            b   = (xx >> (i * 8)) & 0xFFull;
            pop = 0;
            pc = PS_INNER_CHK;
        } else if (pc == PS_INNER_CHK) {
            pc = (b != 0ull) ? PS_INNER_BODY : PS_OUTER_BODY;
        } else if (pc == PS_INNER_BODY) {
            b = b & (b - 1ull);
            pop = pop + 1;
            pc = PS_INNER_CHK;
        } else if (pc == PS_OUTER_BODY) {
            total = total + pop * pop;
            pc = PS_OUTER_INC;
        } else if (pc == PS_OUTER_INC) {
            i = i + 1;
            pc = PS_OUTER_CHK;
        } else if (pc == PS_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popsq64(0xCAFEBABEDEADBEEF)=%d vm_popsq64(0x0102030405060708)=%d\n",
           vm_popsq64_loop_target(0xCAFEBABEDEADBEEFull),
           vm_popsq64_loop_target(0x0102030405060708ull));
    return 0;
}
```
