# vm_four_input_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_four_input_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_four_input_loop.ll`
- **Symbol:** `vm_four_input_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_four_input_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_four_input_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0, R8=0, R9=0 | 0 | 0 | 0 | yes | all zero |
| 2 | RCX=5, RDX=7, R8=11, R9=13 | 6070737 | 6070737 | 6070737 | yes | x=5,y=7,z=11,w=13 |
| 3 | RCX=15, RDX=1, R8=1, R9=0 | 15 | 15 | 15 | yes | oscillation: 16 trips, z=1, w=0 |
| 4 | RCX=1, RDX=1, R8=1, R9=1 | 1 | 1 | 1 | yes | all ones, n=2 |
| 5 | RCX=51966, RDX=47806, R8=57005, R9=64206 | 4147403342 | 4147403342 | 4147403342 | yes | 0xCAFE,0xBABE,0xDEAD,0xFACE |
| 6 | RCX=4294967295, RDX=1, R8=1, R9=1 | 4294967295 | 4294967295 | 4294967295 | yes | x=-1, oscillates back |
| 7 | RCX=305419896, RDX=2596069104, R8=3, R9=5 | 4276205933 | 4276205933 | 4276205933 | yes | x=0x12345678, n=9 |
| 8 | RCX=7, RDX=3, R8=5, R9=11 | 2343751 | 2343751 | 2343751 | yes | x=7, n=8 |
| 9 | RCX=0, RDX=1, R8=2, R9=3 | 5 | 5 | 5 | yes | n=1: (0^1)*2+3=5 |
| 10 | RCX=2147483648, RDX=1073741824, R8=3, R9=7 | 1073741831 | 1073741831 | 1073741831 | yes | x=0x80000000, n=1 |

## Source

```c
/* PC-state VM that takes FOUR input parameters (x in RCX, y in RDX,
 * z in R8, w in R9) and runs a polynomial state recurrence
 *   state = (state ^ y) * z + w
 * for n = (x & 0xF) + 1 iterations starting from state=x.
 * Lift target: vm_four_input_loop_target.
 *
 * Distinct from vm_two_input_loop / vm_three_input_loop: this exercises
 * R9 as a live input (fourth and final Win64 register-passed arg),
 * completing the four-register fastcall convention coverage.
 */
#include <stdio.h>

enum FoVmPc {
    FO_LOAD       = 0,
    FO_INIT       = 1,
    FO_LOOP_CHECK = 2,
    FO_LOOP_BODY  = 3,
    FO_LOOP_INC   = 4,
    FO_HALT       = 5,
};

__declspec(noinline)
int vm_four_input_loop_target(int x, int y, int z, int w) {
    int idx   = 0;
    int n     = 0;
    int state = 0;
    int yy    = 0;
    int zz    = 0;
    int ww    = 0;
    int pc    = FO_LOAD;

    while (1) {
        if (pc == FO_LOAD) {
            n     = (x & 0xF) + 1;
            state = x;
            yy    = y;
            zz    = z;
            ww    = w;
            pc = FO_INIT;
        } else if (pc == FO_INIT) {
            idx = 0;
            pc = FO_LOOP_CHECK;
        } else if (pc == FO_LOOP_CHECK) {
            pc = (idx < n) ? FO_LOOP_BODY : FO_HALT;
        } else if (pc == FO_LOOP_BODY) {
            state = (state ^ yy) * zz + ww;
            pc = FO_LOOP_INC;
        } else if (pc == FO_LOOP_INC) {
            idx = idx + 1;
            pc = FO_LOOP_CHECK;
        } else if (pc == FO_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_four_input(5,7,11,13)=%d vm_four_input(0xCAFE,0xBABE,0xDEAD,0xFACE)=%d\n",
           vm_four_input_loop_target(5, 7, 11, 13),
           vm_four_input_loop_target(0xCAFE, 0xBABE, 0xDEAD, 0xFACE));
    return 0;
}
```
