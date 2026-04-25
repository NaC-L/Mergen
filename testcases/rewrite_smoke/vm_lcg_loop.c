/* PC-state VM running an LCG-style mixed multiply-and-mask recurrence.
 * Lift target: vm_lcg_loop_target.
 * Goal: cover a single-state recurrence whose body mixes multiplication,
 * addition, and a bitmask in one update step:
 *   state = (state * 5 + key + 3) & 0xFF
 * Both the key and the iteration count are derived from x so neither the
 * loop bound nor the recurrence can be folded.
 */
#include <stdio.h>

enum LcgVmPc {
    LG_INIT       = 0,
    LG_LOAD_KEY   = 1,
    LG_LOAD_N     = 2,
    LG_INIT_STATE = 3,
    LG_CHECK      = 4,
    LG_BODY_MUL   = 5,
    LG_BODY_ADD   = 6,
    LG_BODY_MASK  = 7,
    LG_BODY_DEC   = 8,
    LG_HALT       = 9,
};

__declspec(noinline)
int vm_lcg_loop_target(int x) {
    int key   = 0;
    int n     = 0;
    int state = 0;
    int tmp   = 0;
    int pc    = LG_INIT;

    while (1) {
        if (pc == LG_INIT) {
            pc = LG_LOAD_KEY;
        } else if (pc == LG_LOAD_KEY) {
            key = x & 0xFF;
            pc = LG_LOAD_N;
        } else if (pc == LG_LOAD_N) {
            n = x & 0xF;
            pc = LG_INIT_STATE;
        } else if (pc == LG_INIT_STATE) {
            state = 1;
            pc = LG_CHECK;
        } else if (pc == LG_CHECK) {
            pc = (n > 0) ? LG_BODY_MUL : LG_HALT;
        } else if (pc == LG_BODY_MUL) {
            tmp = state * 5;
            pc = LG_BODY_ADD;
        } else if (pc == LG_BODY_ADD) {
            tmp = tmp + key + 3;
            pc = LG_BODY_MASK;
        } else if (pc == LG_BODY_MASK) {
            state = tmp & 0xFF;
            pc = LG_BODY_DEC;
        } else if (pc == LG_BODY_DEC) {
            n = n - 1;
            pc = LG_CHECK;
        } else if (pc == LG_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lcg_loop(7)=%d vm_lcg_loop(255)=%d\n",
           vm_lcg_loop_target(7), vm_lcg_loop_target(255));
    return 0;
}
