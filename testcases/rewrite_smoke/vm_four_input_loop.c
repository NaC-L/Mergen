/* PC-state VM that takes FOUR input parameters (x in RCX, y in RDX,
 * z in R8, w in R9) and runs a polynomial state recurrence
 *   state = (state ^ y) * z + w
 * for n = (x & 0xF) + 1 iterations starting from state=x.
 * Lift target: vm_four_input_loop_target.
 *
 * Distinct from vm_two_input_loop / vm_three_input_loop: this exercises
 * R9 as a live input (fourth and final Win64 register-passed arg),
 * completing the four-register fastcall convention coverage.
 */
#include <stdio.h>

enum FoVmPc {
    FO_LOAD       = 0,
    FO_INIT       = 1,
    FO_LOOP_CHECK = 2,
    FO_LOOP_BODY  = 3,
    FO_LOOP_INC   = 4,
    FO_HALT       = 5,
};

__declspec(noinline)
int vm_four_input_loop_target(int x, int y, int z, int w) {
    int idx   = 0;
    int n     = 0;
    int state = 0;
    int yy    = 0;
    int zz    = 0;
    int ww    = 0;
    int pc    = FO_LOAD;

    while (1) {
        if (pc == FO_LOAD) {
            n     = (x & 0xF) + 1;
            state = x;
            yy    = y;
            zz    = z;
            ww    = w;
            pc = FO_INIT;
        } else if (pc == FO_INIT) {
            idx = 0;
            pc = FO_LOOP_CHECK;
        } else if (pc == FO_LOOP_CHECK) {
            pc = (idx < n) ? FO_LOOP_BODY : FO_HALT;
        } else if (pc == FO_LOOP_BODY) {
            state = (state ^ yy) * zz + ww;
            pc = FO_LOOP_INC;
        } else if (pc == FO_LOOP_INC) {
            idx = idx + 1;
            pc = FO_LOOP_CHECK;
        } else if (pc == FO_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_four_input(5,7,11,13)=%d vm_four_input(0xCAFE,0xBABE,0xDEAD,0xFACE)=%d\n",
           vm_four_input_loop_target(5, 7, 11, 13),
           vm_four_input_loop_target(0xCAFE, 0xBABE, 0xDEAD, 0xFACE));
    return 0;
}
