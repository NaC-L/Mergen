/* PC-state VM that counts distinct runs of 1-bits in the low 16 bits of x.
 * Lift target: vm_runlength_loop_target.
 * Goal: cover a bitwise loop body with a sequential dependency on the
 * previous iteration's bit (run-detection: 1->0 / 0->1 transitions).  Body
 * uses the always-write recipe (runs += start_of_run_predicate) to avoid
 * the multi-counter phi-undef bug.
 */
#include <stdio.h>

enum RlVmPc {
    RL_LOAD       = 0,
    RL_INIT       = 1,
    RL_CHECK      = 2,
    RL_BODY_BIT   = 3,
    RL_BODY_START = 4,
    RL_BODY_ADD   = 5,
    RL_BODY_PREV  = 6,
    RL_BODY_INC   = 7,
    RL_HALT       = 8,
};

__declspec(noinline)
int vm_runlength_loop_target(int x) {
    int idx   = 0;
    int prev  = 0;
    int runs  = 0;
    int bit   = 0;
    int start = 0;
    int pc    = RL_LOAD;

    while (1) {
        if (pc == RL_LOAD) {
            idx = 0;
            prev = 0;
            runs = 0;
            pc = RL_INIT;
        } else if (pc == RL_INIT) {
            pc = RL_CHECK;
        } else if (pc == RL_CHECK) {
            pc = (idx < 16) ? RL_BODY_BIT : RL_HALT;
        } else if (pc == RL_BODY_BIT) {
            bit = (x >> idx) & 1;
            pc = RL_BODY_START;
        } else if (pc == RL_BODY_START) {
            start = bit & (~prev) & 1;
            pc = RL_BODY_ADD;
        } else if (pc == RL_BODY_ADD) {
            runs = runs + start;
            pc = RL_BODY_PREV;
        } else if (pc == RL_BODY_PREV) {
            prev = bit;
            pc = RL_BODY_INC;
        } else if (pc == RL_BODY_INC) {
            idx = idx + 1;
            pc = RL_CHECK;
        } else if (pc == RL_HALT) {
            return runs;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_runlength_loop(0x1234)=%d vm_runlength_loop(0x5555)=%d\n",
           vm_runlength_loop_target(0x1234), vm_runlength_loop_target(0x5555));
    return 0;
}
