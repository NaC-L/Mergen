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
