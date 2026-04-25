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
