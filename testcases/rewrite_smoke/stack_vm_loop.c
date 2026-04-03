/* Harsher stack-based VM with explicit push/pop/add/sub/jnz-style states.
 * Lift target: stack_vm_loop_target.
 * Goal: keep the loop entirely in VM state while modeling a more realistic
 * stack interpreter than the compiler-friendly register/local VM.
 *
 * This version keeps the stack explicit but collapses bookkeeping-only microstates
 * and uses fixed 2-slot stack transitions so the sample remains lli-executable
 * without reintroducing the branchy per-slot dispatcher forest that hit budget 503.
 */
#include <stdio.h>

#define VM_PUSH0(VALUE)                                                          \
    do {                                                                        \
        s0 = (VALUE);                                                           \
        sp = 1;                                                                 \
    } while (0)

#define VM_PUSH1(VALUE)                                                          \
    do {                                                                        \
        s1 = (VALUE);                                                           \
        sp = 2;                                                                 \
    } while (0)

#define VM_POP1(OUT)                                                             \
    do {                                                                        \
        (OUT) = s1;                                                             \
        sp = 1;                                                                 \
    } while (0)

#define VM_POP0(OUT)                                                             \
    do {                                                                        \
        (OUT) = s0;                                                             \
        sp = 0;                                                                 \
    } while (0)

enum StackVmPc {
    VM_EVEN_PUSH_40 = 0,
    VM_EVEN_HALT = 1,

    VM_ODD_INIT_LIMIT = 10,
    VM_ODD_INIT_ACC = 11,
    VM_ODD_INIT_INDEX = 12,
    VM_ODD_SUB_JNZ = 13,
    VM_ODD_BODY_ACC = 14,
    VM_ODD_BODY_INDEX = 15,
    VM_ODD_HALT = 16,
};

__declspec(noinline)
int stack_vm_loop_target(int x) {
    int sp = 0;
    int s0 = 0;
    int s1 = 0;
    int acc = 0;
    int index = 0;
    int limit = 0;
    int pc = (x & 1) ? VM_ODD_INIT_LIMIT : VM_EVEN_PUSH_40;
    int lhs = 0;
    int rhs = 0;
    int cond = 0;

    while (1) {
        if (pc == VM_EVEN_PUSH_40) {
            VM_PUSH0(40);
            pc = VM_EVEN_HALT;
        } else if (pc == VM_EVEN_HALT) {
            VM_POP0(lhs);
            return lhs;
        } else if (pc == VM_ODD_INIT_LIMIT) {
            VM_PUSH0(x & 7);
            VM_POP0(limit);
            pc = VM_ODD_INIT_ACC;
        } else if (pc == VM_ODD_INIT_ACC) {
            VM_PUSH0(0);
            VM_POP0(acc);
            pc = VM_ODD_INIT_INDEX;
        } else if (pc == VM_ODD_INIT_INDEX) {
            VM_PUSH0(0);
            VM_POP0(index);
            pc = VM_ODD_SUB_JNZ;
        } else if (pc == VM_ODD_SUB_JNZ) {
            VM_PUSH0(limit);
            VM_PUSH1(index);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs - rhs);
            VM_POP0(cond);
            pc = (cond != 0) ? VM_ODD_BODY_ACC : VM_ODD_HALT;
        } else if (pc == VM_ODD_BODY_ACC) {
            VM_PUSH0(acc);
            VM_PUSH1(index);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs + rhs);
            VM_POP0(acc);
            pc = VM_ODD_BODY_INDEX;
        } else if (pc == VM_ODD_BODY_INDEX) {
            VM_PUSH0(index);
            VM_PUSH1(1);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs + rhs);
            VM_POP0(index);
            pc = VM_ODD_SUB_JNZ;
        } else if (pc == VM_ODD_HALT) {
            VM_PUSH0(acc);
            VM_POP0(lhs);
            return lhs;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("stack_vm_loop(5)=%d stack_vm_loop(8)=%d\n",
           stack_vm_loop_target(5), stack_vm_loop_target(8));
    return 0;
}
