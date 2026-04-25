/* PC-state VM that computes factorial via a multiplicative loop in VM state.
 * Lift target: vm_factorial_loop_target.
 * Goal: cover a multiplicative recurrence (acc *= i) instead of the additive
 * sum loops in the other VM samples. The loop bound is symbolic (limit = x & 7)
 * so the lifter cannot constant-fold the result.
 */
#include <stdio.h>

enum FactVmPc {
    FV_INIT       = 0,
    FV_LOAD_LIMIT = 1,
    FV_INIT_PROD  = 2,
    FV_INIT_INDEX = 3,
    FV_CHECK      = 4,
    FV_BODY_MUL   = 5,
    FV_BODY_INC   = 6,
    FV_HALT       = 7,
};

__declspec(noinline)
int vm_factorial_loop_target(int x) {
    int limit = 0;
    int prod  = 0;
    int i     = 0;
    int pc    = FV_INIT;

    while (1) {
        if (pc == FV_INIT) {
            pc = FV_LOAD_LIMIT;
        } else if (pc == FV_LOAD_LIMIT) {
            limit = x & 7;
            pc = FV_INIT_PROD;
        } else if (pc == FV_INIT_PROD) {
            prod = 1;
            pc = FV_INIT_INDEX;
        } else if (pc == FV_INIT_INDEX) {
            i = 1;
            pc = FV_CHECK;
        } else if (pc == FV_CHECK) {
            pc = (i <= limit) ? FV_BODY_MUL : FV_HALT;
        } else if (pc == FV_BODY_MUL) {
            prod = prod * i;
            pc = FV_BODY_INC;
        } else if (pc == FV_BODY_INC) {
            i = i + 1;
            pc = FV_CHECK;
        } else if (pc == FV_HALT) {
            return prod;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_factorial_loop(5)=%d vm_factorial_loop(7)=%d\n",
           vm_factorial_loop_target(5), vm_factorial_loop_target(7));
    return 0;
}
