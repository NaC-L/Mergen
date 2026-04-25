# vm_minabs_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_minabs_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_minabs_loop.ll`
- **Symbol:** `vm_minabs_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_minabs_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_minabs_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 128 | 128 | 128 | yes | limit=1, target=-128 |
| 2 | RCX=1 | 128 | 128 | 128 | yes | limit=2, target=-128 |
| 3 | RCX=8 | 128 | 128 | 128 | yes | limit=9, target=-128 |
| 4 | RCX=16 | 127 | 127 | 127 | yes | 0x10: limit=1, target=-127 |
| 5 | RCX=128 | 120 | 120 | 120 | yes | 0x80: limit=1, target=-120 |
| 6 | RCX=255 | 113 | 113 | 113 | yes | 0xFF: limit=16, target=-113 |
| 7 | RCX=2748 | 4 | 4 | 4 | yes | 0xABC: limit=13, target=43 |
| 8 | RCX=3295 | 1 | 1 | 1 | yes | 0xCDF: limit=16, target=77 |
| 9 | RCX=4660 | 93 | 93 | 93 | yes | 0x1234: limit=5, target=-93 |
| 10 | RCX=65535 | 3 | 3 | 3 | yes | 0xFFFF: limit=16, target=127 |
| 11 | RCX=2063 | 0 | 0 | 0 | yes | 0x80F: limit=16, target=0; perfect i=0 |

## Source

```c
/* PC-state VM that tracks the minimum abs() distance from i*13 to a
 * symbolic target across a counted loop.
 * Lift target: vm_minabs_loop_target.
 * Goal: cover a comparison-driven update loop where the predicate is
 * computed via an imported intrinsic call (abs).  Distinct from
 * vm_imported_abs_loop (sums abs values) and vm_minarray_loop (compares
 * raw stack-array elements without a call).
 */
#include <stdio.h>
#include <stdlib.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT       = 1,
    MA_CHECK      = 2,
    MA_BODY_DELTA = 3,
    MA_BODY_CALL  = 4,
    MA_BODY_TEST  = 5,
    MA_BODY_INC   = 6,
    MA_HALT       = 7,
};

__declspec(noinline)
int vm_minabs_loop_target(int x) {
    int limit  = 0;
    int idx    = 0;
    int best   = 0;
    int target = 0;
    int delta  = 0;
    int abs_r  = 0;
    int pc     = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            limit = (x & 0xF) + 1;
            target = ((x >> 4) & 0xFF) - 128;
            best = 256;
            pc = MA_INIT;
        } else if (pc == MA_INIT) {
            idx = 0;
            pc = MA_CHECK;
        } else if (pc == MA_CHECK) {
            pc = (idx < limit) ? MA_BODY_DELTA : MA_HALT;
        } else if (pc == MA_BODY_DELTA) {
            delta = (idx * 13) - target;
            pc = MA_BODY_CALL;
        } else if (pc == MA_BODY_CALL) {
            abs_r = abs(delta);
            pc = MA_BODY_TEST;
        } else if (pc == MA_BODY_TEST) {
            best = (abs_r < best) ? abs_r : best;
            pc = MA_BODY_INC;
        } else if (pc == MA_BODY_INC) {
            idx = idx + 1;
            pc = MA_CHECK;
        } else if (pc == MA_HALT) {
            return best;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_minabs_loop(0xABC)=%d vm_minabs_loop(0xFFFF)=%d\n",
           vm_minabs_loop_target(0xABC), vm_minabs_loop_target(0xFFFF));
    return 0;
}
```
