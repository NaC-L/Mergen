/* PC-state VM computing Fibonacci numbers via a two-register recurrence.
 * Lift target: vm_fibonacci_loop_target.
 * Goal: exercise a loop whose body updates two interdependent state
 * variables (a, b = b, a+b).  Iteration count n = x & 15 is symbolic so
 * the result depends on the input.  Returns fib(n).
 */
#include <stdio.h>

enum FibVmPc {
    FB_INIT       = 0,
    FB_LOAD_N     = 1,
    FB_INIT_REGS  = 2,
    FB_CHECK      = 3,
    FB_BODY_TMP   = 4,
    FB_BODY_SHIFT = 5,
    FB_BODY_DEC   = 6,
    FB_HALT       = 7,
};

__declspec(noinline)
int vm_fibonacci_loop_target(int x) {
    int n   = 0;
    int a   = 0;
    int b   = 0;
    int tmp = 0;
    int pc  = FB_INIT;

    while (1) {
        if (pc == FB_INIT) {
            pc = FB_LOAD_N;
        } else if (pc == FB_LOAD_N) {
            n = x & 15;
            pc = FB_INIT_REGS;
        } else if (pc == FB_INIT_REGS) {
            a = 0;
            b = 1;
            pc = FB_CHECK;
        } else if (pc == FB_CHECK) {
            pc = (n > 0) ? FB_BODY_TMP : FB_HALT;
        } else if (pc == FB_BODY_TMP) {
            tmp = a + b;
            pc = FB_BODY_SHIFT;
        } else if (pc == FB_BODY_SHIFT) {
            a = b;
            b = tmp;
            pc = FB_BODY_DEC;
        } else if (pc == FB_BODY_DEC) {
            n = n - 1;
            pc = FB_CHECK;
        } else if (pc == FB_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_fibonacci_loop(7)=%d vm_fibonacci_loop(12)=%d\n",
           vm_fibonacci_loop_target(7), vm_fibonacci_loop_target(12));
    return 0;
}
