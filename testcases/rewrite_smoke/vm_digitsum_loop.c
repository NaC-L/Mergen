/* PC-state VM that sums the decimal digits of a symbolic input.
 * Lift target: vm_digitsum_loop_target.
 * Goal: cover a non-counted loop terminating on `n != 0`, with both
 * integer divide and modulo by 10 (non-power-of-2 divisor) in the body.
 * Distinct from vm_gcd_loop (different recurrence: n /= 10 vs Euclidean)
 * and vm_powermod_loop (smaller mod constant 13 with shift-driven loop).
 */
#include <stdio.h>

enum DsVmPc {
    DS_LOAD     = 0,
    DS_INIT     = 1,
    DS_CHECK    = 2,
    DS_BODY_DIG = 3,
    DS_BODY_ADD = 4,
    DS_BODY_DIV = 5,
    DS_HALT     = 6,
};

__declspec(noinline)
int vm_digitsum_loop_target(int x) {
    int n     = 0;
    int sum   = 0;
    int digit = 0;
    int pc    = DS_LOAD;

    while (1) {
        if (pc == DS_LOAD) {
            n = x & 0xFFFF;
            sum = 0;
            pc = DS_INIT;
        } else if (pc == DS_INIT) {
            pc = DS_CHECK;
        } else if (pc == DS_CHECK) {
            pc = (n > 0) ? DS_BODY_DIG : DS_HALT;
        } else if (pc == DS_BODY_DIG) {
            digit = n % 10;
            pc = DS_BODY_ADD;
        } else if (pc == DS_BODY_ADD) {
            sum = sum + digit;
            pc = DS_BODY_DIV;
        } else if (pc == DS_BODY_DIV) {
            n = n / 10;
            pc = DS_CHECK;
        } else if (pc == DS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_digitsum_loop(1234)=%d vm_digitsum_loop(65535)=%d\n",
           vm_digitsum_loop_target(1234), vm_digitsum_loop_target(65535));
    return 0;
}
