/* PC-state VM where the body cycles through 4 different operations per
 * iteration based on a sub-state index (state mod 4).
 * Lift target: vm_4state_loop_target.
 * Goal: cover an inner state machine inside the loop body that picks one
 * of four arithmetic ops (add, xor, mul, sub) by an internal phase counter.
 * Distinct from vm_classify_loop (3-way, single-pass) because here the
 * branch is a CYCLIC selector that varies per iteration.
 */
#include <stdio.h>

enum S4VmPc {
    S4_LOAD       = 0,
    S4_INIT       = 1,
    S4_CHECK      = 2,
    S4_DISPATCH   = 3,
    S4_OP_ADD     = 4,
    S4_OP_XOR     = 5,
    S4_OP_MUL     = 6,
    S4_OP_SUB     = 7,
    S4_AFTER      = 8,
    S4_HALT       = 9,
};

__declspec(noinline)
int vm_4state_loop_target(int x) {
    int v     = 0;
    int n     = 0;
    int state = 0;
    int pc    = S4_LOAD;

    while (1) {
        if (pc == S4_LOAD) {
            v = x & 0xFF;
            n = (x >> 8) & 0xF;
            state = 0;
            pc = S4_INIT;
        } else if (pc == S4_INIT) {
            pc = S4_CHECK;
        } else if (pc == S4_CHECK) {
            pc = (n > 0) ? S4_DISPATCH : S4_HALT;
        } else if (pc == S4_DISPATCH) {
            if (state == 0) pc = S4_OP_ADD;
            else if (state == 1) pc = S4_OP_XOR;
            else if (state == 2) pc = S4_OP_MUL;
            else pc = S4_OP_SUB;
        } else if (pc == S4_OP_ADD) {
            v = (v + 7) & 0xFF;
            pc = S4_AFTER;
        } else if (pc == S4_OP_XOR) {
            v = (v ^ 0x5A) & 0xFF;
            pc = S4_AFTER;
        } else if (pc == S4_OP_MUL) {
            v = (v * 3) & 0xFF;
            pc = S4_AFTER;
        } else if (pc == S4_OP_SUB) {
            v = (v - 11) & 0xFF;
            pc = S4_AFTER;
        } else if (pc == S4_AFTER) {
            state = (state + 1) & 3;
            n = n - 1;
            pc = S4_CHECK;
        } else if (pc == S4_HALT) {
            return v;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_4state_loop(0xF00)=%d vm_4state_loop(0xABCD)=%d\n",
           vm_4state_loop_target(0xF00), vm_4state_loop_target(0xABCD));
    return 0;
}
