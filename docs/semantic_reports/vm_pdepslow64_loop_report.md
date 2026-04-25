# vm_pdepslow64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_pdepslow64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_pdepslow64_loop.ll`
- **Symbol:** `vm_pdepslow64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_pdepslow64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_pdepslow64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: src=0, mask=1, no bits set |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: src=1, mask=1, deposit bit 0 |
| 3 | RCX=15 | 1 | 1 | 1 | yes | x=0xF: src=0xF, mask=1, only bit 0 fits |
| 4 | RCX=255 | 1 | 1 | 1 | yes | x=0xFF: mask=1, only bit 0 |
| 5 | RCX=1095216660735 | 255 | 255 | 255 | yes | src=0xFF, mask=0xFF: identity-like |
| 6 | RCX=4294967297 | 1 | 1 | 1 | yes | src=1, mask=1 |
| 7 | RCX=14627333968688430831 | 1119269551 | 1119269551 | 1119269551 | yes | 0xCAFEBABEDEADBEEF |
| 8 | RCX=18446744073709551615 | 4294967295 | 4294967295 | 4294967295 | yes | max u64: src=max32 deposited at all 32 mask positions |
| 9 | RCX=51966 | 0 | 0 | 0 | yes | x=0xCAFE: src=0xCAFE, mask=1 (high zero), bit 0 of src is 0 |
| 10 | RCX=11400714819323198485 | 2285306001 | 2285306001 | 2285306001 | yes | K (golden) |

## Source

```c
/* PC-state VM running an explicit PDEP-style bit-deposit (no intrinsic).
 *   src = x & 0xFFFFFFFF;
 *   mask = (x >> 32) | 1;     // ensure non-zero
 *   result = 0; bit_pos = 0;
 *   for i in 0..64:
 *     if ((mask >> i) & 1):
 *       if ((src >> bit_pos) & 1):
 *         result |= (1 << i);
 *       bit_pos++;
 *   return result;
 * 64-trip fixed loop with two nested bit-tests + conditional bit-deposit.
 * Lift target: vm_pdepslow64_loop_target.
 *
 * Distinct from vm_morton64_loop (fixed every-other-bit spread): the
 * deposit positions are determined by an input-derived MASK, so each
 * call has different scatter pattern.  Bit_pos counter advances only
 * when the mask bit is set - asymmetric loop counter.
 */
#include <stdio.h>
#include <stdint.h>

enum PdVmPc {
    PD_LOAD       = 0,
    PD_INIT       = 1,
    PD_LOOP_CHECK = 2,
    PD_LOOP_BODY  = 3,
    PD_LOOP_INC   = 4,
    PD_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pdepslow64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      bit_pos = 0;
    uint64_t src     = 0;
    uint64_t mask    = 0;
    uint64_t result  = 0;
    int      pc      = PD_LOAD;

    while (1) {
        if (pc == PD_LOAD) {
            src    = x & 0xFFFFFFFFull;
            mask   = (x >> 32) | 1ull;
            result = 0ull;
            bit_pos = 0;
            pc = PD_INIT;
        } else if (pc == PD_INIT) {
            idx = 0;
            pc = PD_LOOP_CHECK;
        } else if (pc == PD_LOOP_CHECK) {
            pc = (idx < 64) ? PD_LOOP_BODY : PD_HALT;
        } else if (pc == PD_LOOP_BODY) {
            if (((mask >> idx) & 1ull) != 0ull) {
                if (((src >> bit_pos) & 1ull) != 0ull) {
                    result = result | (1ull << idx);
                }
                bit_pos = bit_pos + 1;
            }
            pc = PD_LOOP_INC;
        } else if (pc == PD_LOOP_INC) {
            idx = idx + 1;
            pc = PD_LOOP_CHECK;
        } else if (pc == PD_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pdepslow64(0xCAFEBABEDEADBEEF)=%llu vm_pdepslow64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_pdepslow64_loop_target(0xCAFEBABEDEADBEEFull),
           (unsigned long long)vm_pdepslow64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
