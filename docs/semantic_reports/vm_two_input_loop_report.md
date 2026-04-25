# vm_two_input_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_two_input_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_two_input_loop.ll`
- **Symbol:** `vm_two_input_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_two_input_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_two_input_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | x=0, y=0 |
| 2 | RCX=1, RDX=0 | 196608 | 196608 | 196608 | yes | x=1, y=0 |
| 3 | RCX=0, RDX=1 | 1 | 1 | 1 | yes | x=0, y=1 |
| 4 | RCX=1, RDX=1 | 131073 | 131073 | 131073 | yes | x=1, y=1 |
| 5 | RCX=31, RDX=4660 | 1345208320 | 1345208320 | 1345208320 | yes | x=0x1F (n=32), y=0x1234 |
| 6 | RCX=51966, RDX=47806 | 2532031230 | 2532031230 | 2532031230 | yes | 0xCAFE,0xBABE |
| 7 | RCX=1048576, RDX=305419896 | 306468472 | 306468472 | 306468472 | yes | x=0x100000, y=0x12345678 |
| 8 | RCX=4294967295, RDX=4294967295 | 66060320 | 66060320 | 66060320 | yes | both -1 |
| 9 | RCX=2147483648, RDX=1431655765 | 3579139413 | 3579139413 | 3579139413 | yes | x=0x80000000, y=0x55555555 |
| 10 | RCX=5, RDX=7 | 14024739 | 14024739 | 14024739 | yes | x=5, y=7 |

## Source

```c
/* PC-state VM that takes TWO input parameters (x in RCX, y in RDX) and
 * runs an LCG-style state mixer for n = (x & 0x1F) + 1 iterations,
 * XOR-folding state into a result.
 * Lift target: vm_two_input_loop_target.
 *
 * Distinct from existing samples: every other vm_*_loop takes a single
 * int and uses RCX only.  This sample exercises RDX as a live input
 * across the lifted body.
 */
#include <stdio.h>

enum TiVmPc {
    TI_LOAD       = 0,
    TI_INIT       = 1,
    TI_LOOP_CHECK = 2,
    TI_LOOP_BODY  = 3,
    TI_LOOP_INC   = 4,
    TI_HALT       = 5,
};

__declspec(noinline)
int vm_two_input_loop_target(int x, int y) {
    int idx    = 0;
    int n      = 0;
    int state  = 0;
    int result = 0;
    int yy     = 0;
    int pc     = TI_LOAD;

    while (1) {
        if (pc == TI_LOAD) {
            n      = (x & 0x1F) + 1;
            state  = x;
            yy     = y;
            result = 0;
            pc = TI_INIT;
        } else if (pc == TI_INIT) {
            idx = 0;
            pc = TI_LOOP_CHECK;
        } else if (pc == TI_LOOP_CHECK) {
            pc = (idx < n) ? TI_LOOP_BODY : TI_HALT;
        } else if (pc == TI_LOOP_BODY) {
            state  = state * 0x10001 + yy;
            result = result ^ state;
            pc = TI_LOOP_INC;
        } else if (pc == TI_LOOP_INC) {
            idx = idx + 1;
            pc = TI_LOOP_CHECK;
        } else if (pc == TI_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_two_input(0xCAFE,0xBABE)=%d vm_two_input(5,7)=%d\n",
           vm_two_input_loop_target(0xCAFE, 0xBABE),
           vm_two_input_loop_target(5, 7));
    return 0;
}
```
