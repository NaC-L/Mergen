/* PC-state VM with a conditional branch inside the loop body.
 * Lift target: vm_branchy_loop_target.
 * Goal: keep a VM-shaped dispatcher with a real loop AND a data-dependent
 * branch in the loop body (parity test on the loop induction variable).
 * Counts how many odd values exist in [0, limit) where limit = x & 0xF.
 */
#include <stdio.h>

enum BranchVmPc {
    BV_INIT        = 0,
    BV_LOAD_LIMIT  = 1,
    BV_CHECK_LIMIT = 2,
    BV_TEST_PARITY = 3,
    BV_INC_COUNT   = 4,
    BV_INC_INDEX   = 5,
    BV_HALT        = 6,
};

__declspec(noinline)
int vm_branchy_loop_target(int x) {
    int i      = 0;
    int count  = 0;
    int limit  = 0;
    int parity = 0;
    int pc     = BV_LOAD_LIMIT;

    while (1) {
        if (pc == BV_LOAD_LIMIT) {
            i = 0;
            count = 0;
            limit = x & 0xF;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_CHECK_LIMIT) {
            pc = (i < limit) ? BV_TEST_PARITY : BV_HALT;
        } else if (pc == BV_TEST_PARITY) {
            parity = i & 1;
            pc = (parity != 0) ? BV_INC_COUNT : BV_INC_INDEX;
        } else if (pc == BV_INC_COUNT) {
            count = count + 1;
            pc = BV_INC_INDEX;
        } else if (pc == BV_INC_INDEX) {
            i = i + 1;
            pc = BV_CHECK_LIMIT;
        } else if (pc == BV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_branchy_loop(10)=%d vm_branchy_loop(15)=%d\n",
           vm_branchy_loop_target(10), vm_branchy_loop_target(15));
    return 0;
}
