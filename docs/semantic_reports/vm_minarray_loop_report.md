# vm_minarray_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_minarray_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_minarray_loop.ll`
- **Symbol:** `vm_minarray_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_minarray_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_minarray_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, data=[0] |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=2, data=[1,14] |
| 3 | RCX=2 | 2 | 2 | 2 | yes | limit=3, data=[2,15,28] |
| 4 | RCX=7 | 7 | 7 | 7 | yes | limit=8, full array |
| 5 | RCX=16 | 16 | 16 | 16 | yes | limit=1, data=[16] |
| 6 | RCX=66 | 66 | 66 | 66 | yes | limit=3, data=[66,79,92] |
| 7 | RCX=128 | 128 | 128 | 128 | yes | limit=1, data=[128] |
| 8 | RCX=200 | 200 | 200 | 200 | yes | limit=1, data=[200] |
| 9 | RCX=255 | 12 | 12 | 12 | yes | limit=8, wraparound puts 12 in middle |
| 10 | RCX=256 | 0 | 0 | 0 | yes | limit=1, data=[0] (mask drops bit 8) |
| 11 | RCX=2748 | 188 | 188 | 188 | yes | limit=5, data starting at 188 |
| 12 | RCX=3840 | 0 | 0 | 0 | yes | limit=1, data=[0] (low byte 0) |

## Source

```c
/* PC-state VM that fills a stack array from a symbolic input then scans it
 * for the minimum byte value.
 * Lift target: vm_minarray_loop_target.
 * Goal: cover a comparison-driven update loop (running minimum) over an
 * array whose contents depend on x, with the trip count also derived from x
 * so the lifter cannot fully unroll the search.
 */
#include <stdio.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT_IDX   = 1,
    MA_FILL_CHECK = 2,
    MA_FILL_BODY  = 3,
    MA_FILL_INC   = 4,
    MA_INIT_MIN   = 5,
    MA_SCAN_CHECK = 6,
    MA_SCAN_LOAD  = 7,
    MA_SCAN_TEST  = 8,
    MA_SCAN_UPDATE = 9,
    MA_SCAN_INC   = 10,
    MA_HALT       = 11,
};

__declspec(noinline)
int vm_minarray_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int elt   = 0;
    int best  = 0;
    int pc    = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            limit = (x & 7) + 1;
            pc = MA_INIT_IDX;
        } else if (pc == MA_INIT_IDX) {
            idx = 0;
            pc = MA_FILL_CHECK;
        } else if (pc == MA_FILL_CHECK) {
            pc = (idx < limit) ? MA_FILL_BODY : MA_INIT_MIN;
        } else if (pc == MA_FILL_BODY) {
            data[idx] = (x + idx * 13) & 0xFF;
            pc = MA_FILL_INC;
        } else if (pc == MA_FILL_INC) {
            idx = idx + 1;
            pc = MA_FILL_CHECK;
        } else if (pc == MA_INIT_MIN) {
            best = data[0];
            idx = 1;
            pc = MA_SCAN_CHECK;
        } else if (pc == MA_SCAN_CHECK) {
            pc = (idx < limit) ? MA_SCAN_LOAD : MA_HALT;
        } else if (pc == MA_SCAN_LOAD) {
            elt = data[idx];
            pc = MA_SCAN_TEST;
        } else if (pc == MA_SCAN_TEST) {
            pc = (elt < best) ? MA_SCAN_UPDATE : MA_SCAN_INC;
        } else if (pc == MA_SCAN_UPDATE) {
            best = elt;
            pc = MA_SCAN_INC;
        } else if (pc == MA_SCAN_INC) {
            idx = idx + 1;
            pc = MA_SCAN_CHECK;
        } else if (pc == MA_HALT) {
            return best;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_minarray_loop(0xFF)=%d vm_minarray_loop(0xABC)=%d\n",
           vm_minarray_loop_target(0xFF), vm_minarray_loop_target(0xABC));
    return 0;
}
```
