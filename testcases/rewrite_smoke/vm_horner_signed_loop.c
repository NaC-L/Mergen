/* PC-state VM evaluating a polynomial with signed coefficients via Horner's
 * method.
 * Lift target: vm_horner_signed_loop_target.
 * Goal: cover signed multiply-and-add inside a loop where the coefficient
 * array contains negative values.  Distinct from vm_polynomial_loop (all
 * positive coefficients): tests sign extension of small constants stored
 * to a stack array and consumed by mul.  p(t) = t^3 - 2t^2 + 3t - 4.
 */
#include <stdio.h>

enum HsVmPc {
    HS_LOAD       = 0,
    HS_INIT       = 1,
    HS_INIT_COEF  = 2,
    HS_CHECK      = 3,
    HS_BODY_LOAD  = 4,
    HS_BODY_MUL   = 5,
    HS_BODY_ADD   = 6,
    HS_BODY_INC   = 7,
    HS_HALT       = 8,
};

__declspec(noinline)
int vm_horner_signed_loop_target(int x) {
    int coef[4];
    int t      = 0;
    int i      = 0;
    int result = 0;
    int c      = 0;
    int prod   = 0;
    int pc     = HS_LOAD;

    while (1) {
        if (pc == HS_LOAD) {
            t = (x & 7) + 1;
            i = 0;
            result = 0;
            pc = HS_INIT_COEF;
        } else if (pc == HS_INIT_COEF) {
            coef[0] = 1;
            coef[1] = -2;
            coef[2] = 3;
            coef[3] = -4;
            pc = HS_CHECK;
        } else if (pc == HS_CHECK) {
            pc = (i < 4) ? HS_BODY_LOAD : HS_HALT;
        } else if (pc == HS_BODY_LOAD) {
            c = coef[i];
            pc = HS_BODY_MUL;
        } else if (pc == HS_BODY_MUL) {
            prod = result * t;
            pc = HS_BODY_ADD;
        } else if (pc == HS_BODY_ADD) {
            result = prod + c;
            pc = HS_BODY_INC;
        } else if (pc == HS_BODY_INC) {
            i = i + 1;
            pc = HS_CHECK;
        } else if (pc == HS_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_horner_signed_loop(0)=%d vm_horner_signed_loop(7)=%d\n",
           vm_horner_signed_loop_target(0), vm_horner_signed_loop_target(7));
    return 0;
}
