# vm_clz64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_clz64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_clz64_loop.ll`
- **Symbol:** `vm_clz64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_clz64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_clz64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 64 | 64 | 64 | yes | x=0: special-case 64 |
| 2 | RCX=1 | 63 | 63 | 63 | yes | x=1: 63 leading zeros (max trip) |
| 3 | RCX=2 | 62 | 62 | 62 | yes | x=2: 62 |
| 4 | RCX=128 | 56 | 56 | 56 | yes | x=0x80: 56 |
| 5 | RCX=65536 | 47 | 47 | 47 | yes | x=0x10000: 47 |
| 6 | RCX=4294967296 | 31 | 31 | 31 | yes | x=2^32: 31 |
| 7 | RCX=9223372036854775808 | 0 | 0 | 0 | yes | x=2^63: 0 (MSB set) |
| 8 | RCX=3405691582 | 32 | 32 | 32 | yes | x=0xCAFEBABE: 32 |
| 9 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | max u64: 0 |
| 10 | RCX=11400714819323198485 | 0 | 0 | 0 | yes | x=K (golden, MSB set): 0 |

## Source

```c
/* PC-state VM running an i64 count-leading-zeros via shift-loop.
 *   if (x == 0) return 64;
 *   count = 0;
 *   while ((x & 0x8000000000000000) == 0) { x <<= 1; count++; }
 *   return count;
 * Variable trip 0..63 (or short-circuit 64 for zero).
 * Lift target: vm_clz64_loop_target.
 *
 * Companion to vm_cttz64_loop (which counts trailing zeros via shift-right).
 * Distinct from vm_imported_clz_loop (i32 _BitScanReverse intrinsic):
 * exercises explicit shift-left + MSB-test on full i64 in a variable-trip loop.
 */
#include <stdio.h>
#include <stdint.h>

enum ClVmPc {
    CL_LOAD       = 0,
    CL_INIT       = 1,
    CL_ZERO_CHECK = 2,
    CL_LOOP_CHECK = 3,
    CL_LOOP_BODY  = 4,
    CL_HALT       = 5,
};

__declspec(noinline)
int vm_clz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = CL_LOAD;

    while (1) {
        if (pc == CL_LOAD) {
            state = x;
            count = 0;
            pc = CL_ZERO_CHECK;
        } else if (pc == CL_ZERO_CHECK) {
            if (state == 0ull) {
                count = 64;
                pc = CL_HALT;
            } else {
                pc = CL_LOOP_CHECK;
            }
        } else if (pc == CL_LOOP_CHECK) {
            pc = ((state & 0x8000000000000000ull) == 0ull) ? CL_LOOP_BODY : CL_HALT;
        } else if (pc == CL_LOOP_BODY) {
            state = state << 1;
            count = count + 1;
            pc = CL_LOOP_CHECK;
        } else if (pc == CL_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_clz64(1)=%d vm_clz64(0x8000000000000000)=%d\n",
           vm_clz64_loop_target(1ull),
           vm_clz64_loop_target(0x8000000000000000ull));
    return 0;
}
```
