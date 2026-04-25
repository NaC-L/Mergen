# vm_pextslow64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 9/9 equivalent
- **Source:** `testcases/rewrite_smoke/vm_pextslow64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_pextslow64_loop.ll`
- **Symbol:** `vm_pextslow64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_pextslow64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_pextslow64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | x=1: src bit 0 = 1, mask bit 0 = 0 |
| 3 | RCX=255 | 15 | 15 | 15 | yes | x=0xFF: extract odd bits 1,3,5,7 |
| 4 | RCX=51966 | 191 | 191 | 191 | yes | x=0xCAFE |
| 5 | RCX=3405691582 | 49151 | 49151 | 49151 | yes | x=0xCAFEBABE |
| 6 | RCX=1311768467463790320 | 2696280958 | 2696280958 | 2696280958 | yes | 0x123456789ABCDEF0 |
| 7 | RCX=18446744073709551615 | 4294967295 | 4294967295 | 4294967295 | yes | max u64: extract 32 bits = 0xFFFFFFFF |
| 8 | RCX=11400714819323198485 | 3043943525 | 3043943525 | 3043943525 | yes | K (golden) |
| 9 | RCX=12297829381654935552 | 65535 | 65535 | 65535 | yes | 0xAAAAAAAA00000000: extract 16 bits |

## Source

```c
/* PC-state VM running an explicit PEXT-style parallel bit-extract.
 *   src = x;
 *   mask = 0xAAAAAAAAAAAAAAAA ^ (x >> 32);   // input-perturbed mask
 *   if (mask == 0) mask = 1;
 *   result = 0; bit_pos = 0;
 *   for i in 0..64:
 *     if ((mask >> i) & 1):
 *       if ((src >> i) & 1):
 *         result |= (1 << bit_pos);
 *       bit_pos++;
 *   return result;
 * Lift target: vm_pextslow64_loop_target.
 *
 * Distinct from vm_pdepslow64_loop (deposit/scatter): this is the
 * INVERSE - bits at mask-set positions in src are PACKED into low-order
 * bits of result.  The deposit position depends on a running counter
 * that advances asymmetrically.
 */
#include <stdio.h>
#include <stdint.h>

enum PxVmPc {
    PX_LOAD       = 0,
    PX_INIT       = 1,
    PX_LOOP_CHECK = 2,
    PX_LOOP_BODY  = 3,
    PX_LOOP_INC   = 4,
    PX_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pextslow64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      bit_pos = 0;
    uint64_t src     = 0;
    uint64_t mask    = 0;
    uint64_t result  = 0;
    int      pc      = PX_LOAD;

    while (1) {
        if (pc == PX_LOAD) {
            src    = x;
            mask   = 0xAAAAAAAAAAAAAAAAull ^ (x >> 32);
            if (mask == 0ull) {
                mask = 1ull;
            }
            result = 0ull;
            bit_pos = 0;
            pc = PX_INIT;
        } else if (pc == PX_INIT) {
            idx = 0;
            pc = PX_LOOP_CHECK;
        } else if (pc == PX_LOOP_CHECK) {
            pc = (idx < 64) ? PX_LOOP_BODY : PX_HALT;
        } else if (pc == PX_LOOP_BODY) {
            if (((mask >> idx) & 1ull) != 0ull) {
                if (((src >> idx) & 1ull) != 0ull) {
                    result = result | (1ull << bit_pos);
                }
                bit_pos = bit_pos + 1;
            }
            pc = PX_LOOP_INC;
        } else if (pc == PX_LOOP_INC) {
            idx = idx + 1;
            pc = PX_LOOP_CHECK;
        } else if (pc == PX_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pextslow64(0xCAFEBABE)=%llu vm_pextslow64(max)=%llu\n",
           (unsigned long long)vm_pextslow64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_pextslow64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
