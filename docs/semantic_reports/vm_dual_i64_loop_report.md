# vm_dual_i64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dual_i64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dual_i64_loop.ll`
- **Symbol:** `vm_dual_i64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dual_i64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dual_i64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | x=0, y=0 |
| 2 | RCX=1, RDX=2 | 15 | 15 | 15 | yes | x=1, y=2, n=2 |
| 3 | RCX=51966, RDX=47806 | 17848445641019346730 | 17848445641019346730 | 17848445641019346730 | yes | x=0xCAFE, y=0xBABE |
| 4 | RCX=18446744073709551615, RDX=1 | 18446744073709551606 | 18446744073709551606 | 18446744073709551606 | yes | x=max u64 (n=8), y=1: linear |
| 5 | RCX=1, RDX=18446744073709551615 | 18446744073709551614 | 18446744073709551614 | 18446744073709551614 | yes | x=1 (n=2), y=max u64 |
| 6 | RCX=1311768467463790320, RDX=18364758544493064720 | 9002574064070388976 | 9002574064070388976 | 9002574064070388976 | yes | 0x123..F0, 0xFEDC..10 |
| 7 | RCX=7, RDX=11 | 2722357788 | 2722357788 | 2722357788 | yes | x=7, y=11, n=8 |
| 8 | RCX=65537, RDX=65537 | 4295163906 | 4295163906 | 4295163906 | yes | both 0x10001, n=2 |
| 9 | RCX=9223372036854775808, RDX=9223372036854775808 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | both 2^63 |
| 10 | RCX=3, RDX=11400714819323198485 | 11583513995942334250 | 11583513995942334250 | 11583513995942334250 | yes | x=3, y=K (golden ratio), n=4 |

## Source

```c
/* PC-state VM with TWO full uint64_t inputs (x in RCX, y in RDX).
 * Runs state = state * y + x for n = (x & 7) + 1 iterations starting
 * from state = x ^ y, returning the full uint64_t state.
 * Lift target: vm_dual_i64_loop_target.
 *
 * Distinct from vm_mixed_args_loop (i32+i64) and vm_two_input_loop
 * (i32+i32): here BOTH arguments are full 64-bit live across the loop
 * body, with a 64-bit return.  Exercises the lifter's 64-bit register
 * tracking for both RCX and RDX simultaneously.
 */
#include <stdio.h>
#include <stdint.h>

enum DqVmPc {
    DQ_LOAD       = 0,
    DQ_INIT       = 1,
    DQ_LOOP_CHECK = 2,
    DQ_LOOP_BODY  = 3,
    DQ_LOOP_INC   = 4,
    DQ_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_dual_i64_loop_target(uint64_t x, uint64_t y) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    uint64_t xx    = 0;
    uint64_t yy    = 0;
    int      pc    = DQ_LOAD;

    while (1) {
        if (pc == DQ_LOAD) {
            n     = (int)(x & 7ull) + 1;
            xx    = x;
            yy    = y;
            state = x ^ y;
            pc = DQ_INIT;
        } else if (pc == DQ_INIT) {
            idx = 0;
            pc = DQ_LOOP_CHECK;
        } else if (pc == DQ_LOOP_CHECK) {
            pc = (idx < n) ? DQ_LOOP_BODY : DQ_HALT;
        } else if (pc == DQ_LOOP_BODY) {
            state = state * yy + xx;
            pc = DQ_LOOP_INC;
        } else if (pc == DQ_LOOP_INC) {
            idx = idx + 1;
            pc = DQ_LOOP_CHECK;
        } else if (pc == DQ_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dual_i64(7,11)=0x%llx vm_dual_i64(0xCAFE,0xBABE)=0x%llx\n",
           (unsigned long long)vm_dual_i64_loop_target(7ull, 11ull),
           (unsigned long long)vm_dual_i64_loop_target(0xCAFEull, 0xBABEull));
    return 0;
}
```
