/* Tiny dummy-VM-style state machine around a real local loop.
 * Lift target: dummy_vm_loop_target.
 * Goal: keep a VM-shaped dispatch shell while preserving a normal counted loop
 * inside one handler, so loop-generalization regressions cannot silently
 * collapse it into unresolved control flow.
 */
#include <stdio.h>

__declspec(noinline)
int dummy_vm_loop_target(int x) {
    int opcode = x & 1;
    int acc = 0;

    while (1) {
        switch (opcode) {
        case 0:
            acc = 40;
            opcode = 2;
            break;
        case 1: {
            int limit = x & 7;
            for (int i = 0; i < limit; i++)
                acc += i;
            opcode = 2;
            break;
        }
        case 2:
            return acc;
        default:
            return -1;
        }
    }
}

int main(void) {
    printf("dummy_vm_loop(5)=%d dummy_vm_loop(8)=%d\n",
           dummy_vm_loop_target(5), dummy_vm_loop_target(8));
    return 0;
}
