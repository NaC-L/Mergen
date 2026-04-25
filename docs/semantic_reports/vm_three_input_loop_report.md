# vm_three_input_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_three_input_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_three_input_loop.ll`
- **Symbol:** `vm_three_input_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_three_input_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_three_input_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0, R8=0 | 0 | 0 | 0 | yes | all zero |
| 2 | RCX=1, RDX=0, R8=2 | 4 | 4 | 4 | yes | x=1, n=2, doubling |
| 3 | RCX=0, RDX=1, R8=0 | 1 | 1 | 1 | yes | y=1, z=0: collapses to y |
| 4 | RCX=5, RDX=7, R8=11 | 10097897 | 10097897 | 10097897 | yes | x=5, y=7, z=11 |
| 5 | RCX=15, RDX=1, R8=1 | 31 | 31 | 31 | yes | x=0xF (n=16), z=1: linear |
| 6 | RCX=51966, RDX=47806, R8=57005 | 295439328 | 295439328 | 295439328 | yes | 0xCAFE,0xBABE,0xDEAD |
| 7 | RCX=4294967295, RDX=4294967295, R8=4294967295 | 4294967295 | 4294967295 | 4294967295 | yes | all -1: cycles |
| 8 | RCX=65537, RDX=65537, R8=65537 | 393219 | 393219 | 393219 | yes | x=0x10001 (n=2) |
| 9 | RCX=7, RDX=3, R8=5 | 3027343 | 3027343 | 3027343 | yes | x=7, n=8 |
| 10 | RCX=2147483648, RDX=1431655765, R8=3 | 3579139413 | 3579139413 | 3579139413 | yes | x=0x80000000, n=1 |

## Source

```c
/* PC-state VM that takes THREE input parameters (x in RCX, y in RDX,
 * z in R8) and runs an LCG-style state recurrence
 *   state = state * z + y
 * for n = (x & 0xF) + 1 iterations starting from state=x.
 * Lift target: vm_three_input_loop_target.
 *
 * Distinct from vm_two_input_loop: this exercises R8 as a live input
 * (third Win64 register-passed arg) across the lifted body.
 */
#include <stdio.h>

enum ThVmPc {
    TH_LOAD       = 0,
    TH_INIT       = 1,
    TH_LOOP_CHECK = 2,
    TH_LOOP_BODY  = 3,
    TH_LOOP_INC   = 4,
    TH_HALT       = 5,
};

__declspec(noinline)
int vm_three_input_loop_target(int x, int y, int z) {
    int idx   = 0;
    int n     = 0;
    int state = 0;
    int yy    = 0;
    int zz    = 0;
    int pc    = TH_LOAD;

    while (1) {
        if (pc == TH_LOAD) {
            n     = (x & 0xF) + 1;
            state = x;
            yy    = y;
            zz    = z;
            pc = TH_INIT;
        } else if (pc == TH_INIT) {
            idx = 0;
            pc = TH_LOOP_CHECK;
        } else if (pc == TH_LOOP_CHECK) {
            pc = (idx < n) ? TH_LOOP_BODY : TH_HALT;
        } else if (pc == TH_LOOP_BODY) {
            state = state * zz + yy;
            pc = TH_LOOP_INC;
        } else if (pc == TH_LOOP_INC) {
            idx = idx + 1;
            pc = TH_LOOP_CHECK;
        } else if (pc == TH_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_three_input(5,7,11)=%d vm_three_input(0xCAFE,0xBABE,0xDEAD)=%d\n",
           vm_three_input_loop_target(5, 7, 11),
           vm_three_input_loop_target(0xCAFE, 0xBABE, 0xDEAD));
    return 0;
}
```
