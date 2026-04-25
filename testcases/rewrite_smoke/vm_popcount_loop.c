/* PC-state VM that counts set bits via a shift+and+add loop.
 * Lift target: vm_popcount_loop_target.
 * Goal: cover a bitwise-driven loop whose termination test is "value reached
 * zero" rather than a counted compare.  Operates on the low 8 bits of x so
 * the trip count is bounded but symbolic.
 */
#include <stdio.h>

enum PopVmPc {
    PV_INIT      = 0,
    PV_LOAD_VAL  = 1,
    PV_INIT_CNT  = 2,
    PV_CHECK     = 3,
    PV_BODY_BIT  = 4,
    PV_BODY_ADD  = 5,
    PV_BODY_SHR  = 6,
    PV_HALT      = 7,
};

__declspec(noinline)
int vm_popcount_loop_target(int x) {
    int v   = 0;
    int cnt = 0;
    int bit = 0;
    int pc  = PV_INIT;

    while (1) {
        if (pc == PV_INIT) {
            pc = PV_LOAD_VAL;
        } else if (pc == PV_LOAD_VAL) {
            v = x & 0xFF;
            pc = PV_INIT_CNT;
        } else if (pc == PV_INIT_CNT) {
            cnt = 0;
            pc = PV_CHECK;
        } else if (pc == PV_CHECK) {
            pc = (v != 0) ? PV_BODY_BIT : PV_HALT;
        } else if (pc == PV_BODY_BIT) {
            bit = v & 1;
            pc = PV_BODY_ADD;
        } else if (pc == PV_BODY_ADD) {
            cnt = cnt + bit;
            pc = PV_BODY_SHR;
        } else if (pc == PV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = PV_CHECK;
        } else if (pc == PV_HALT) {
            return cnt;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popcount_loop(0xAA)=%d vm_popcount_loop(0xFF)=%d\n",
           vm_popcount_loop_target(0xAA), vm_popcount_loop_target(0xFF));
    return 0;
}
