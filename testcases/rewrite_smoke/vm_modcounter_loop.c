/* PC-state VM with a counter that wraps modulo 7 every iteration.
 * Lift target: vm_modcounter_loop_target.
 * Goal: cover a single-state recurrence whose body is one mod operation
 * per step (counter = (counter + step) % 7).  Distinct from vm_lcg_loop
 * (mul+add+mask) and vm_powermod_loop (mul+conditional-mod): the constant
 * divisor is non-power-of-two and the recurrence has no multiplication.
 */
#include <stdio.h>

enum McVmPc {
    MC_LOAD       = 0,
    MC_INIT       = 1,
    MC_CHECK      = 2,
    MC_BODY_ADD   = 3,
    MC_BODY_MOD   = 4,
    MC_BODY_DEC   = 5,
    MC_HALT       = 6,
};

__declspec(noinline)
int vm_modcounter_loop_target(int x) {
    int counter = 0;
    int step    = 0;
    int n       = 0;
    int tmp     = 0;
    int pc      = MC_LOAD;

    while (1) {
        if (pc == MC_LOAD) {
            counter = x & 0xFF;
            step = ((x >> 8) & 0xF) | 1;
            n = (x >> 12) & 0xF;
            pc = MC_INIT;
        } else if (pc == MC_INIT) {
            pc = MC_CHECK;
        } else if (pc == MC_CHECK) {
            pc = (n > 0) ? MC_BODY_ADD : MC_HALT;
        } else if (pc == MC_BODY_ADD) {
            tmp = counter + step;
            pc = MC_BODY_MOD;
        } else if (pc == MC_BODY_MOD) {
            counter = tmp % 7;
            pc = MC_BODY_DEC;
        } else if (pc == MC_BODY_DEC) {
            n = n - 1;
            pc = MC_CHECK;
        } else if (pc == MC_HALT) {
            return counter;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_modcounter_loop(0xF300)=%d vm_modcounter_loop(0x1234)=%d\n",
           vm_modcounter_loop_target(0xF300), vm_modcounter_loop_target(0x1234));
    return 0;
}
