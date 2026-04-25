# vm_cttz64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_cttz64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_cttz64_loop.ll`
- **Symbol:** `vm_cttz64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_cttz64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_cttz64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 64 | 64 | 64 | yes | x=0: special-case 64 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | x=1: 0 trailing zeros |
| 3 | RCX=2 | 1 | 1 | 1 | yes | x=2: 1 |
| 4 | RCX=4 | 2 | 2 | 2 | yes | x=4: 2 |
| 5 | RCX=8 | 3 | 3 | 3 | yes | x=8: 3 |
| 6 | RCX=4294967296 | 32 | 32 | 32 | yes | x=2^32: 32 |
| 7 | RCX=9223372036854775808 | 63 | 63 | 63 | yes | x=2^63: 63 (max) |
| 8 | RCX=3405691582 | 1 | 1 | 1 | yes | x=0xCAFEBABE: 1 |
| 9 | RCX=18446744073709551614 | 1 | 1 | 1 | yes | x=max-1: 1 |
| 10 | RCX=11400714819323198485 | 0 | 0 | 0 | yes | x=K (golden): 0 (odd) |

## Source

```c
/* PC-state VM running an i64 count-trailing-zeros via shift-loop.
 *   if (x == 0) return 64;
 *   count = 0;
 *   while ((x & 1) == 0) { x >>= 1; count++; }
 *   return count;
 * Variable trip count = ctz(x), bounded 0..63 (or short-circuit 64 for zero).
 * Lift target: vm_cttz64_loop_target.
 *
 * Distinct from vm_ctz_loop (i32) and vm_imported_cttz_loop (i32 _BitScanForward
 * intrinsic): exercises the same shape on full i64 with explicit shift-and-test
 * rather than the intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_ZERO_CHECK = 2,
    CZ_LOOP_CHECK = 3,
    CZ_LOOP_BODY  = 4,
    CZ_HALT       = 5,
};

__declspec(noinline)
int vm_cttz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            state = x;
            count = 0;
            pc = CZ_ZERO_CHECK;
        } else if (pc == CZ_ZERO_CHECK) {
            if (state == 0ull) {
                count = 64;
                pc = CZ_HALT;
            } else {
                pc = CZ_LOOP_CHECK;
            }
        } else if (pc == CZ_LOOP_CHECK) {
            pc = ((state & 1ull) == 0ull) ? CZ_LOOP_BODY : CZ_HALT;
        } else if (pc == CZ_LOOP_BODY) {
            state = state >> 1;
            count = count + 1;
            pc = CZ_LOOP_CHECK;
        } else if (pc == CZ_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_cttz64(0x100000000)=%d vm_cttz64(0x8000000000000000)=%d\n",
           vm_cttz64_loop_target(0x100000000ull),
           vm_cttz64_loop_target(0x8000000000000000ull));
    return 0;
}
```
