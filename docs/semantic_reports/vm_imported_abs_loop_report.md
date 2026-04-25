# vm_imported_abs_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_abs_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_abs_loop.ll`
- **Symbol:** `vm_imported_abs_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_abs_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_abs_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, threshold=0, delta=0 |
| 2 | RCX=1 | 17 | 17 | 17 | yes | limit=2, threshold=0, sum \|0\|+\|17\| |
| 3 | RCX=16 | 2 | 2 | 2 | yes | 0x10: limit=1, threshold=2 |
| 4 | RCX=32 | 4 | 4 | 4 | yes | 0x20: limit=1, threshold=4 |
| 5 | RCX=64 | 8 | 8 | 8 | yes | 0x40: limit=1, threshold=8 |
| 6 | RCX=128 | 16 | 16 | 16 | yes | 0x80: limit=1, threshold=16 |
| 7 | RCX=255 | 318 | 318 | 318 | yes | 0xFF: limit=8 |
| 8 | RCX=291 | 72 | 72 | 72 | yes | 0x123: limit=4 |
| 9 | RCX=4660 | 180 | 180 | 180 | yes | 0x1234: limit=5 |
| 10 | RCX=65535 | 1564 | 1564 | 1564 | yes | 0xFFFF: limit=8 |

## Source

```c
/* PC-state VM whose loop body calls the imported `abs()` from msvcrt.
 * Lift target: vm_imported_abs_loop_target.
 * Goal: cover a VM dispatcher whose handler issues an indirect-thunk call
 * into a runtime DLL inside the loop, then accumulates the imported call's
 * return value into VM state.  This is the canonical real-obfuscation
 * shape: VM body wraps a real CRT call.
 */
#include <stdio.h>
#include <stdlib.h>

enum AbVmPc {
    AB_LOAD       = 0,
    AB_INIT       = 1,
    AB_CHECK      = 2,
    AB_BODY_DELTA = 3,
    AB_BODY_CALL  = 4,
    AB_BODY_ADD   = 5,
    AB_BODY_INC   = 6,
    AB_HALT       = 7,
};

__declspec(noinline)
int vm_imported_abs_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int delta = 0;
    int abs_result = 0;
    int threshold = 0;
    int pc    = AB_LOAD;

    while (1) {
        if (pc == AB_LOAD) {
            limit = (x & 7) + 1;
            threshold = (x >> 3) & 0xFF;
            sum = 0;
            pc = AB_INIT;
        } else if (pc == AB_INIT) {
            idx = 0;
            pc = AB_CHECK;
        } else if (pc == AB_CHECK) {
            pc = (idx < limit) ? AB_BODY_DELTA : AB_HALT;
        } else if (pc == AB_BODY_DELTA) {
            delta = (idx * 17) - threshold;
            pc = AB_BODY_CALL;
        } else if (pc == AB_BODY_CALL) {
            abs_result = abs(delta);
            pc = AB_BODY_ADD;
        } else if (pc == AB_BODY_ADD) {
            sum = sum + abs_result;
            pc = AB_BODY_INC;
        } else if (pc == AB_BODY_INC) {
            idx = idx + 1;
            pc = AB_CHECK;
        } else if (pc == AB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_abs_loop(0x10)=%d vm_imported_abs_loop(0x40)=%d\n",
           vm_imported_abs_loop_target(0x10), vm_imported_abs_loop_target(0x40));
    return 0;
}
```
