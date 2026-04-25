/* PC-state VM that applies a Rule-90-like cellular automaton step to an
 * 8-bit state.
 * Lift target: vm_ca_loop_target.
 * Goal: cover a single-state recurrence whose body combines a left-shift
 * and a right-shift via XOR (state' = (state<<1) ^ (state>>1)).  Distinct
 * from vm_lfsr_loop (single shift + conditional XOR) and vm_rotate_loop
 * (shift+or for rotation): here the linear XOR couples both shift
 * directions every iteration.
 */
#include <stdio.h>

enum CaVmPc {
    CA_LOAD       = 0,
    CA_INIT       = 1,
    CA_CHECK      = 2,
    CA_BODY_LEFT  = 3,
    CA_BODY_RIGHT = 4,
    CA_BODY_XOR   = 5,
    CA_BODY_MASK  = 6,
    CA_BODY_DEC   = 7,
    CA_HALT       = 8,
};

__declspec(noinline)
int vm_ca_loop_target(int x) {
    int state = 0;
    int n     = 0;
    int left  = 0;
    int right = 0;
    int pc    = CA_LOAD;

    while (1) {
        if (pc == CA_LOAD) {
            state = x & 0xFF;
            n = (x >> 8) & 7;
            pc = CA_INIT;
        } else if (pc == CA_INIT) {
            pc = CA_CHECK;
        } else if (pc == CA_CHECK) {
            pc = (n > 0) ? CA_BODY_LEFT : CA_HALT;
        } else if (pc == CA_BODY_LEFT) {
            left = state << 1;
            pc = CA_BODY_RIGHT;
        } else if (pc == CA_BODY_RIGHT) {
            right = (int)((unsigned)state >> 1);
            pc = CA_BODY_XOR;
        } else if (pc == CA_BODY_XOR) {
            state = left ^ right;
            pc = CA_BODY_MASK;
        } else if (pc == CA_BODY_MASK) {
            state = state & 0xFF;
            pc = CA_BODY_DEC;
        } else if (pc == CA_BODY_DEC) {
            n = n - 1;
            pc = CA_CHECK;
        } else if (pc == CA_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_ca_loop(0x701)=%d vm_ca_loop(0x755)=%d\n",
           vm_ca_loop_target(0x701), vm_ca_loop_target(0x755));
    return 0;
}
