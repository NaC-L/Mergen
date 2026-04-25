/* PC-state VM with a reverse-induction counted loop.
 * Lift target: vm_countdown_loop_target.
 * Goal: exercise loop detection for a loop whose induction variable *decreases*
 * and whose bound is a symbolic countdown rather than a rising compare.
 * Computes the triangular number sum(1..n) where n = x & 0xF, but builds it
 * by counting down from n to 1 instead of up.
 */
#include <stdio.h>

enum CdVmPc {
    CD_INIT       = 0,
    CD_LOAD_COUNT = 1,
    CD_INIT_SUM   = 2,
    CD_CHECK      = 3,
    CD_BODY_ADD   = 4,
    CD_BODY_DEC   = 5,
    CD_HALT       = 6,
};

__declspec(noinline)
int vm_countdown_loop_target(int x) {
    int count = 0;
    int sum   = 0;
    int pc    = CD_INIT;

    while (1) {
        if (pc == CD_INIT) {
            pc = CD_LOAD_COUNT;
        } else if (pc == CD_LOAD_COUNT) {
            count = x & 0xF;
            pc = CD_INIT_SUM;
        } else if (pc == CD_INIT_SUM) {
            sum = 0;
            pc = CD_CHECK;
        } else if (pc == CD_CHECK) {
            pc = (count > 0) ? CD_BODY_ADD : CD_HALT;
        } else if (pc == CD_BODY_ADD) {
            sum = sum + count;
            pc = CD_BODY_DEC;
        } else if (pc == CD_BODY_DEC) {
            count = count - 1;
            pc = CD_CHECK;
        } else if (pc == CD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_countdown_loop(10)=%d vm_countdown_loop(15)=%d\n",
           vm_countdown_loop_target(10), vm_countdown_loop_target(15));
    return 0;
}
