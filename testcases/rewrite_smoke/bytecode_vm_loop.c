/* Compiler-friendly VM with the loop implemented in VM program-counter state.
 * Lift target: bytecode_vm_loop_target.
 * Goal: keep the loop inside interpreter state instead of native source control
 * flow, while avoiding external bytecode loads and compiler jump tables.
 */
#include <stdio.h>

enum FriendlyVmPc {
    VM_EVEN_CONST = 0,
    VM_EVEN_HALT = 1,
    VM_ODD_LOAD_LIMIT = 10,
    VM_ODD_CLEAR_ACC = 11,
    VM_ODD_CLEAR_INDEX = 12,
    VM_ODD_CHECK = 13,
    VM_ODD_BODY = 14,
    VM_ODD_HALT = 15,
};

__declspec(noinline)
int bytecode_vm_loop_target(int x) {
    int pc = (x & 1) ? VM_ODD_LOAD_LIMIT : VM_EVEN_CONST;
    int acc = 0;
    int index = 0;
    int limit = 0;

    while (1) {
        if (pc == VM_EVEN_CONST) {
            acc = 40;
            pc = VM_EVEN_HALT;
        } else if (pc == VM_EVEN_HALT) {
            return acc;
        } else if (pc == VM_ODD_LOAD_LIMIT) {
            limit = x & 7;
            pc = VM_ODD_CLEAR_ACC;
        } else if (pc == VM_ODD_CLEAR_ACC) {
            acc = 0;
            pc = VM_ODD_CLEAR_INDEX;
        } else if (pc == VM_ODD_CLEAR_INDEX) {
            index = 0;
            pc = VM_ODD_CHECK;
        } else if (pc == VM_ODD_CHECK) {
            pc = (index < limit) ? VM_ODD_BODY : VM_ODD_HALT;
        } else if (pc == VM_ODD_BODY) {
            acc += index;
            index += 1;
            pc = VM_ODD_CHECK;
        } else if (pc == VM_ODD_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("bytecode_vm_loop(5)=%d bytecode_vm_loop(8)=%d\n",
           bytecode_vm_loop_target(5), bytecode_vm_loop_target(8));
    return 0;
}
