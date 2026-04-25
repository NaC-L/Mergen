# vm_classify_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_classify_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_classify_loop.ll`
- **Symbol:** `vm_classify_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_classify_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_classify_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 10 | 10 | 10 | yes | n=1, v=-7: 1 neg |
| 2 | RCX=1 | 20 | 20 | 20 | yes | n=2, all neg |
| 3 | RCX=7 | 71 | 71 | 71 | yes | n=8, 1 zero + 7 neg |
| 4 | RCX=8 | 100 | 100 | 100 | yes | n=1, v=1: 1 pos |
| 5 | RCX=119 | 62 | 62 | 62 | yes | n=8, 6 neg + 2 zero |
| 6 | RCX=136 | 100 | 100 | 100 | yes | n=1, v=1 |
| 7 | RCX=240 | 10 | 10 | 10 | yes | n=1, v=-7 |
| 8 | RCX=255 | 260 | 260 | 260 | yes | n=8, 2 pos + 6 neg |
| 9 | RCX=291 | 40 | 40 | 40 | yes | n=4, all neg |
| 10 | RCX=11259375 | 620 | 620 | 620 | yes | 0xABCDEF: n=8, 6 pos + 2 neg |

## Source

```c
/* PC-state VM with a three-way branch in the loop body (sign classifier).
 * Lift target: vm_classify_loop_target.
 * Goal: cover a loop body that splits to one of three handlers and merges
 * back, with each handler adding a different constant into a single packed
 * accumulator (avoids the multi-counter phi-undef regression seen with
 * separate pos/neg/zer slots in the early-halt path).  Result encodes
 * pos*100 + neg*10 + zer.
 */
#include <stdio.h>

enum ClsVmPc {
    CL_LOAD       = 0,
    CL_INIT       = 1,
    CL_CHECK      = 2,
    CL_BODY_LOAD  = 3,
    CL_BODY_TEST_POS = 4,
    CL_BODY_TEST_ZERO = 5,
    CL_ADD_POS    = 6,
    CL_ADD_NEG    = 7,
    CL_ADD_ZER    = 8,
    CL_BODY_INC   = 9,
    CL_HALT       = 10,
};

__declspec(noinline)
int vm_classify_loop_target(int x) {
    int n      = 0;
    int idx    = 0;
    int acc    = 0;
    int v      = 0;
    int shift  = 0;
    int pc     = CL_LOAD;

    while (1) {
        if (pc == CL_LOAD) {
            n = (x & 7) + 1;
            idx = 0;
            acc = 0;
            pc = CL_INIT;
        } else if (pc == CL_INIT) {
            pc = CL_CHECK;
        } else if (pc == CL_CHECK) {
            pc = (idx < n) ? CL_BODY_LOAD : CL_HALT;
        } else if (pc == CL_BODY_LOAD) {
            shift = idx * 4;
            v = ((x >> shift) & 0xF) - 7;
            pc = CL_BODY_TEST_POS;
        } else if (pc == CL_BODY_TEST_POS) {
            pc = (v > 0) ? CL_ADD_POS : CL_BODY_TEST_ZERO;
        } else if (pc == CL_BODY_TEST_ZERO) {
            pc = (v == 0) ? CL_ADD_ZER : CL_ADD_NEG;
        } else if (pc == CL_ADD_POS) {
            acc = acc + 100;
            pc = CL_BODY_INC;
        } else if (pc == CL_ADD_NEG) {
            acc = acc + 10;
            pc = CL_BODY_INC;
        } else if (pc == CL_ADD_ZER) {
            acc = acc + 1;
            pc = CL_BODY_INC;
        } else if (pc == CL_BODY_INC) {
            idx = idx + 1;
            pc = CL_CHECK;
        } else if (pc == CL_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_classify_loop(0x77)=%d vm_classify_loop(0xFF)=%d\n",
           vm_classify_loop_target(0x77), vm_classify_loop_target(0xFF));
    return 0;
}
```
