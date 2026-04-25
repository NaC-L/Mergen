/* Switch-dispatched VM with a counted loop on the odd handler.
 * Lift target: vm_switch_dispatch_loop_target.
 * Goal: cover the case where the compiler lowers the handler dispatcher to a
 * jump table (switch on dense opcode ids) instead of an if-else chain.  The
 * odd path is a counted sum loop; the even path returns a constant handler.
 */
#include <stdio.h>

enum SwitchVmPc {
    SV_EVEN_CONST     = 0,
    SV_EVEN_HALT      = 1,
    SV_ODD_LOAD_LIMIT = 2,
    SV_ODD_INIT_ACC   = 3,
    SV_ODD_INIT_IDX   = 4,
    SV_ODD_CHECK      = 5,
    SV_ODD_BODY_ADD   = 6,
    SV_ODD_BODY_INC   = 7,
    SV_ODD_HALT       = 8,
};

__declspec(noinline)
int vm_switch_dispatch_loop_target(int x) {
    int acc   = 0;
    int idx   = 0;
    int limit = 0;
    int pc    = (x & 1) ? SV_ODD_LOAD_LIMIT : SV_EVEN_CONST;

    while (1) {
        switch (pc) {
        case SV_EVEN_CONST:
            acc = 111;
            pc = SV_EVEN_HALT;
            break;
        case SV_EVEN_HALT:
            return acc;
        case SV_ODD_LOAD_LIMIT:
            limit = (x >> 1) & 7;
            pc = SV_ODD_INIT_ACC;
            break;
        case SV_ODD_INIT_ACC:
            acc = 0;
            pc = SV_ODD_INIT_IDX;
            break;
        case SV_ODD_INIT_IDX:
            idx = 0;
            pc = SV_ODD_CHECK;
            break;
        case SV_ODD_CHECK:
            pc = (idx < limit) ? SV_ODD_BODY_ADD : SV_ODD_HALT;
            break;
        case SV_ODD_BODY_ADD:
            acc = acc + idx;
            pc = SV_ODD_BODY_INC;
            break;
        case SV_ODD_BODY_INC:
            idx = idx + 1;
            pc = SV_ODD_CHECK;
            break;
        case SV_ODD_HALT:
            return acc;
        default:
            return -1;
        }
    }
}

int main(void) {
    printf("vm_switch_dispatch_loop(5)=%d vm_switch_dispatch_loop(11)=%d\n",
           vm_switch_dispatch_loop_target(5), vm_switch_dispatch_loop_target(11));
    return 0;
}
