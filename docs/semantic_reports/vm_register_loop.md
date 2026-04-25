# vm_register_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_register_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_register_loop.ll`
- **Symbol:** `vm_register_loop_target`
- **IR size:** 57 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 40 | 40 | pass | even path: constant handler |
| 2 | RCX=2 | 40 | 40 | pass | even path: constant handler (bit1 set) |
| 3 | RCX=1 | 0 | 0 | pass | odd path: limit=0, empty loop |
| 4 | RCX=3 | 0 | 0 | pass | odd path: limit=1, loop body adds 0 |
| 5 | RCX=5 | 1 | 1 | pass | odd path: limit=2, sum 0+1 |
| 6 | RCX=7 | 3 | 3 | pass | odd path: limit=3, sum 0+1+2 |
| 7 | RCX=9 | 6 | 6 | pass | odd path: limit=4, sum 0..3 |
| 8 | RCX=11 | 10 | 10 | pass | odd path: limit=5, sum 0..4 |
| 9 | RCX=13 | 15 | 15 | pass | odd path: limit=6, sum 0..5 |
| 10 | RCX=15 | 21 | 21 | pass | odd path: limit=7, sum 0..6 |

## Source

```c
/* Toy register-machine VM with explicit register file and arithmetic opcodes.
 * Lift target: vm_register_loop_target.
 * Goal: keep a register-bank dispatch shell while preserving a real loop in
 * VM state.  The even path returns a constant handler; the odd path runs a
 * register VM program that accumulates 0..(limit-1) into r2, where limit is
 * derived from the symbolic input so the loop bound cannot be folded.
 */
#include <stdio.h>

enum RegVmPc {
    REG_VM_EVEN_CONST     = 0,
    REG_VM_EVEN_HALT      = 1,

    REG_VM_ODD_LOAD_LIMIT = 10,  /* r0 = (x >> 1) & 7 */
    REG_VM_ODD_CLEAR_I    = 11,  /* r1 = 0            */
    REG_VM_ODD_CLEAR_ACC  = 12,  /* r2 = 0            */
    REG_VM_ODD_CHECK      = 13,  /* if r1 < r0 -> BODY else HALT */
    REG_VM_ODD_BODY_ADD   = 14,  /* r2 += r1          */
    REG_VM_ODD_BODY_INC   = 15,  /* r1 += 1           */
    REG_VM_ODD_HALT       = 16,
};

__declspec(noinline)
int vm_register_loop_target(int x) {
    int r0 = 0;  /* limit */
    int r1 = 0;  /* index */
    int r2 = 0;  /* accumulator */
    int r3 = 0;  /* scratch */
    int pc = (x & 1) ? REG_VM_ODD_LOAD_LIMIT : REG_VM_EVEN_CONST;

    while (1) {
        if (pc == REG_VM_EVEN_CONST) {
            r2 = 40;
            pc = REG_VM_EVEN_HALT;
        } else if (pc == REG_VM_EVEN_HALT) {
            return r2;
        } else if (pc == REG_VM_ODD_LOAD_LIMIT) {
            r0 = (x >> 1) & 7;
            pc = REG_VM_ODD_CLEAR_I;
        } else if (pc == REG_VM_ODD_CLEAR_I) {
            r1 = 0;
            pc = REG_VM_ODD_CLEAR_ACC;
        } else if (pc == REG_VM_ODD_CLEAR_ACC) {
            r2 = 0;
            pc = REG_VM_ODD_CHECK;
        } else if (pc == REG_VM_ODD_CHECK) {
            r3 = r0 - r1;
            pc = (r3 > 0) ? REG_VM_ODD_BODY_ADD : REG_VM_ODD_HALT;
        } else if (pc == REG_VM_ODD_BODY_ADD) {
            r2 = r2 + r1;
            pc = REG_VM_ODD_BODY_INC;
        } else if (pc == REG_VM_ODD_BODY_INC) {
            r1 = r1 + 1;
            pc = REG_VM_ODD_CHECK;
        } else if (pc == REG_VM_ODD_HALT) {
            return r2;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_register_loop(5)=%d vm_register_loop(11)=%d\n",
           vm_register_loop_target(5), vm_register_loop_target(11));
    return 0;
}
```
