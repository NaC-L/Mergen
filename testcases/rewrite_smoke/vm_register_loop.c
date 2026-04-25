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
