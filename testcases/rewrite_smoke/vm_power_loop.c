/* PC-state VM computing base^exp via repeated multiplication.
 * Lift target: vm_power_loop_target.
 * Goal: cover a multiplicative loop with TWO symbolic operands
 * (base = (x & 7) + 1, exp = (x >> 3) & 3) where the loop body multiplies
 * by a runtime value rather than the induction variable.
 */
#include <stdio.h>

enum PowVmPc {
    PW_INIT       = 0,
    PW_LOAD_BASE  = 1,
    PW_LOAD_EXP   = 2,
    PW_INIT_RES   = 3,
    PW_CHECK      = 4,
    PW_BODY_MUL   = 5,
    PW_BODY_DEC   = 6,
    PW_HALT       = 7,
};

__declspec(noinline)
int vm_power_loop_target(int x) {
    int base = 0;
    int exp  = 0;
    int res  = 0;
    int pc   = PW_INIT;

    while (1) {
        if (pc == PW_INIT) {
            pc = PW_LOAD_BASE;
        } else if (pc == PW_LOAD_BASE) {
            base = (x & 7) + 1;
            pc = PW_LOAD_EXP;
        } else if (pc == PW_LOAD_EXP) {
            exp = (x >> 3) & 3;
            pc = PW_INIT_RES;
        } else if (pc == PW_INIT_RES) {
            res = 1;
            pc = PW_CHECK;
        } else if (pc == PW_CHECK) {
            pc = (exp > 0) ? PW_BODY_MUL : PW_HALT;
        } else if (pc == PW_BODY_MUL) {
            res = res * base;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_DEC) {
            exp = exp - 1;
            pc = PW_CHECK;
        } else if (pc == PW_HALT) {
            return res;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_power_loop(23)=%d vm_power_loop(31)=%d\n",
           vm_power_loop_target(23), vm_power_loop_target(31));
    return 0;
}
