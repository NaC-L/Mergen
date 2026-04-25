# vm_morton64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_morton64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_morton64_loop.ll`
- **Symbol:** `vm_morton64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_morton64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_morton64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: bit 0 stays at 0 |
| 3 | RCX=2 | 4 | 4 | 4 | yes | x=2: bit 1 -> bit 2 |
| 4 | RCX=3 | 5 | 5 | 5 | yes | x=3 = bit 0 + bit 1 -> 1+4 = 5 |
| 5 | RCX=255 | 21845 | 21845 | 21845 | yes | x=0xFF -> 0x5555 |
| 6 | RCX=4294967295 | 6148914691236517205 | 6148914691236517205 | 6148914691236517205 | yes | x=0xFFFFFFFF -> 0x5555555555555555 alternating |
| 7 | RCX=51966 | 1346655572 | 1346655572 | 1346655572 | yes | x=0xCAFE -> 0x50445554 |
| 8 | RCX=3405691582 | 5783841641878275412 | 5783841641878275412 | 5783841641878275412 | yes | 0xCAFEBABE |
| 9 | RCX=2863311530 | 4919131752989213764 | 4919131752989213764 | 4919131752989213764 | yes | 0xAAAAAAAA -> 0x4444444444444444 |
| 10 | RCX=1431655765 | 1229782938247303441 | 1229782938247303441 | 1229782938247303441 | yes | 0x55555555 -> 0x1111111111111111 |

## Source

```c
/* PC-state VM running an i64 Morton (Z-order) bit-spread of low 32 bits
 * to 64 bits.  For each of 32 input bits, place bit i of input at bit
 * position 2*i of output (leaving 2*i+1 as zero).  32-trip fixed loop.
 *   result = 0;
 *   for i in 0..32:
 *     bit = (state >> i) & 1
 *     result |= bit << (2*i)
 *   return result;
 * Lift target: vm_morton64_loop_target.
 *
 * Distinct from vm_bswap64_loop (whole-byte permute) and
 * vm_nibrev64_loop (whole-nibble permute): exercises a 1-bit-stride
 * fan-out where each bit is placed at a different even position.  The
 * lifter likely cannot recognize this as any LLVM intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum MoVmPc {
    MO_LOAD       = 0,
    MO_INIT       = 1,
    MO_LOOP_CHECK = 2,
    MO_LOOP_BODY  = 3,
    MO_LOOP_INC   = 4,
    MO_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_morton64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = MO_LOAD;

    while (1) {
        if (pc == MO_LOAD) {
            state  = x & 0xFFFFFFFFull;
            result = 0ull;
            pc = MO_INIT;
        } else if (pc == MO_INIT) {
            idx = 0;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_LOOP_CHECK) {
            pc = (idx < 32) ? MO_LOOP_BODY : MO_HALT;
        } else if (pc == MO_LOOP_BODY) {
            uint64_t bit = (state >> idx) & 1ull;
            result = result | (bit << (2 * idx));
            pc = MO_LOOP_INC;
        } else if (pc == MO_LOOP_INC) {
            idx = idx + 1;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_morton64(0xFFFFFFFF)=%llu vm_morton64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_morton64_loop_target(0xFFFFFFFFull),
           (unsigned long long)vm_morton64_loop_target(0xCAFEBABEull));
    return 0;
}
```
