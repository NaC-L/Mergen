# vm_prefix_sum_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_prefix_sum_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_prefix_sum_loop.ll`
- **Symbol:** `vm_prefix_sum_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_prefix_sum_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_prefix_sum_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, sole element 0 |
| 2 | RCX=1 | 3 | 3 | 3 | yes | limit=2: data=[1,2], prefix=[1,3] |
| 3 | RCX=2 | 9 | 9 | 9 | yes | limit=3: data=[2,3,4], prefix end=9 |
| 4 | RCX=7 | 84 | 84 | 84 | yes | limit=8: data=[7,8,..,14] sum 84 |
| 5 | RCX=15 | 36 | 36 | 36 | yes | limit=8: data=[15,0,1,..,6] wrap, sum 36 |
| 6 | RCX=16 | 0 | 0 | 0 | yes | limit=1, sole=0 (mask drops bit 4) |
| 7 | RCX=64 | 0 | 0 | 0 | yes | limit=1, sole=0 (low byte mask) |
| 8 | RCX=85 | 45 | 45 | 45 | yes | limit=6: data=[5,6,7,8,9,10] sum 45 |
| 9 | RCX=160 | 0 | 0 | 0 | yes | limit=1, sole=0 |
| 10 | RCX=255 | 36 | 36 | 36 | yes | limit=8: data=[15,0,..,6] wrap |
| 11 | RCX=4660 | 30 | 30 | 30 | yes | 0x1234: limit=5, data=[4,5,6,7,8] sum 30 |

## Source

```c
/* PC-state VM that fills a stack array and then walks it computing an
 * in-place running prefix sum.
 * Lift target: vm_prefix_sum_loop_target.
 * Goal: cover a two-phase VM where the second loop *writes back* into the
 * stack array each iteration (data[i] += data[i-1]).  Distinct from
 * vm_minarray_loop where the second pass only reads.
 */
#include <stdio.h>

enum PsVmPc {
    PS_LOAD       = 0,
    PS_INIT_FILL  = 1,
    PS_FILL_CHECK = 2,
    PS_FILL_BODY  = 3,
    PS_FILL_INC   = 4,
    PS_INIT_SCAN  = 5,
    PS_SCAN_CHECK = 6,
    PS_SCAN_LOAD  = 7,
    PS_SCAN_STORE = 8,
    PS_SCAN_INC   = 9,
    PS_TAIL       = 10,
    PS_HALT       = 11,
};

__declspec(noinline)
int vm_prefix_sum_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int prev  = 0;
    int cur   = 0;
    int sum   = 0;
    int pc    = PS_LOAD;

    while (1) {
        if (pc == PS_LOAD) {
            limit = (x & 7) + 1;
            pc = PS_INIT_FILL;
        } else if (pc == PS_INIT_FILL) {
            idx = 0;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_FILL_CHECK) {
            pc = (idx < limit) ? PS_FILL_BODY : PS_INIT_SCAN;
        } else if (pc == PS_FILL_BODY) {
            data[idx] = (x + idx) & 0xF;
            pc = PS_FILL_INC;
        } else if (pc == PS_FILL_INC) {
            idx = idx + 1;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_INIT_SCAN) {
            idx = 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_SCAN_CHECK) {
            pc = (idx < limit) ? PS_SCAN_LOAD : PS_TAIL;
        } else if (pc == PS_SCAN_LOAD) {
            prev = data[idx - 1];
            cur = data[idx];
            pc = PS_SCAN_STORE;
        } else if (pc == PS_SCAN_STORE) {
            data[idx] = prev + cur;
            pc = PS_SCAN_INC;
        } else if (pc == PS_SCAN_INC) {
            idx = idx + 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_TAIL) {
            sum = data[limit - 1];
            pc = PS_HALT;
        } else if (pc == PS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_prefix_sum_loop(0x55)=%d vm_prefix_sum_loop(0x1234)=%d\n",
           vm_prefix_sum_loop_target(0x55), vm_prefix_sum_loop_target(0x1234));
    return 0;
}
```
