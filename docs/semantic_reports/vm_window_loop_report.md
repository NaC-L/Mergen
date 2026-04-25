# vm_window_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_window_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_window_loop.ll`
- **Symbol:** `vm_window_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_window_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_window_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 165 | 165 | 165 | yes | limit=3, data=[0,0x37,0x6E] |
| 2 | RCX=1 | 329 | 329 | 329 | yes | limit=4 |
| 3 | RCX=7 | 557 | 557 | 557 | yes | limit=10 |
| 4 | RCX=170 | 523 | 523 | 523 | yes | 0xAA: limit=5 |
| 5 | RCX=255 | 600 | 600 | 600 | yes | 0xFF: limit=10 |
| 6 | RCX=85 | 447 | 447 | 447 | yes | 0x55: limit=8 |
| 7 | RCX=291 | 466 | 466 | 466 | yes | 0x123: limit=6 |
| 8 | RCX=4660 | 467 | 467 | 467 | yes | 0x1234: limit=7 |
| 9 | RCX=196 | 609 | 609 | 609 | yes | 0xC4: limit=7 |
| 10 | RCX=128 | 549 | 549 | 549 | yes | 0x80: limit=3 |
| 11 | RCX=55 | 541 | 541 | 541 | yes | 0x37: limit=10 |

## Source

```c
/* PC-state VM that finds the maximum sum of a 3-element sliding window
 * over a symbolic-content stack array.
 * Lift target: vm_window_loop_target.
 * Goal: cover a loop body that loads THREE adjacent stack-array elements
 * (data[i], data[i+1], data[i+2]) per iteration and updates a running max.
 * Distinct from vm_dupcount_loop (loads two elements) and vm_minarray_loop
 * (loads one).
 */
#include <stdio.h>

enum WnVmPc {
    WN_LOAD       = 0,
    WN_INIT_FILL  = 1,
    WN_FILL_CHECK = 2,
    WN_FILL_BODY  = 3,
    WN_FILL_INC   = 4,
    WN_INIT_SCAN  = 5,
    WN_SCAN_CHECK = 6,
    WN_SCAN_LOAD  = 7,
    WN_SCAN_SUM   = 8,
    WN_SCAN_MAX   = 9,
    WN_SCAN_INC   = 10,
    WN_HALT       = 11,
};

__declspec(noinline)
int vm_window_loop_target(int x) {
    int data[10];
    int limit = 0;
    int idx   = 0;
    int a     = 0;
    int b     = 0;
    int c     = 0;
    int s     = 0;
    int mx    = 0;
    int pc    = WN_LOAD;

    while (1) {
        if (pc == WN_LOAD) {
            limit = (x & 7) + 3;
            mx = 0;
            pc = WN_INIT_FILL;
        } else if (pc == WN_INIT_FILL) {
            idx = 0;
            pc = WN_FILL_CHECK;
        } else if (pc == WN_FILL_CHECK) {
            pc = (idx < limit) ? WN_FILL_BODY : WN_INIT_SCAN;
        } else if (pc == WN_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x37)) & 0xFF;
            pc = WN_FILL_INC;
        } else if (pc == WN_FILL_INC) {
            idx = idx + 1;
            pc = WN_FILL_CHECK;
        } else if (pc == WN_INIT_SCAN) {
            idx = 0;
            pc = WN_SCAN_CHECK;
        } else if (pc == WN_SCAN_CHECK) {
            pc = (idx <= limit - 3) ? WN_SCAN_LOAD : WN_HALT;
        } else if (pc == WN_SCAN_LOAD) {
            a = data[idx];
            b = data[idx + 1];
            c = data[idx + 2];
            pc = WN_SCAN_SUM;
        } else if (pc == WN_SCAN_SUM) {
            s = a + b + c;
            pc = WN_SCAN_MAX;
        } else if (pc == WN_SCAN_MAX) {
            mx = (s > mx) ? s : mx;
            pc = WN_SCAN_INC;
        } else if (pc == WN_SCAN_INC) {
            idx = idx + 1;
            pc = WN_SCAN_CHECK;
        } else if (pc == WN_HALT) {
            return mx;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_window_loop(0xFF)=%d vm_window_loop(0x1234)=%d\n",
           vm_window_loop_target(0xFF), vm_window_loop_target(0x1234));
    return 0;
}
```
