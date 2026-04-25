/* PC-state VM running Newton's method for integer square root.
 * Lift target: vm_isqrt_loop_target.
 * Goal: cover a non-counted loop whose body divides by a *loop-variable*
 * (`n / a`), distinct from vm_digitsum_loop (constant divisor 10) and
 * vm_gcd_loop (modulo by loop variable but no division of a different
 * symbolic value). Termination uses a < b strict-decrease check.
 */
#include <stdio.h>

enum SqrtVmPc {
    SQ_LOAD       = 0,
    SQ_INIT       = 1,
    SQ_CHECK      = 2,
    SQ_BODY_DIV   = 3,
    SQ_BODY_SUM   = 4,
    SQ_BODY_HALF  = 5,
    SQ_BODY_SHIFT = 6,
    SQ_HALT       = 7,
};

__declspec(noinline)
int vm_isqrt_loop_target(int x) {
    int n   = 0;
    int a   = 0;
    int b   = 0;
    int q   = 0;
    int sum = 0;
    int pc  = SQ_LOAD;

    while (1) {
        if (pc == SQ_LOAD) {
            n = x & 0xFFFF;
            a = n;
            b = (n + 1) / 2;
            pc = SQ_CHECK;
        } else if (pc == SQ_CHECK) {
            pc = (b < a) ? SQ_BODY_DIV : SQ_HALT;
        } else if (pc == SQ_BODY_DIV) {
            a = b;
            q = n / a;
            pc = SQ_BODY_SUM;
        } else if (pc == SQ_BODY_SUM) {
            sum = a + q;
            pc = SQ_BODY_HALF;
        } else if (pc == SQ_BODY_HALF) {
            b = sum / 2;
            pc = SQ_CHECK;
        } else if (pc == SQ_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_isqrt_loop(100)=%d vm_isqrt_loop(65535)=%d\n",
           vm_isqrt_loop_target(100), vm_isqrt_loop_target(65535));
    return 0;
}
