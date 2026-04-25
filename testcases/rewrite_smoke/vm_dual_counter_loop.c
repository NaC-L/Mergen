/* PC-state VM whose loop body updates two independent counters per iteration.
 * Lift target: vm_dual_counter_loop_target.
 * Goal: cover a loop where the parity-driven branch sends control to one of
 * two distinct increment handlers and merges back, so the lifter must
 * preserve two independent phi nodes inside the loop body.  Returns
 * even_count * 100 + odd_count for limit = x & 0xF.
 */
#include <stdio.h>

enum DualVmPc {
    DV_INIT       = 0,
    DV_LOAD_LIMIT = 1,
    DV_INIT_CTRS  = 2,
    DV_INIT_IDX   = 3,
    DV_CHECK      = 4,
    DV_TEST_PAR   = 5,
    DV_INC_EVEN   = 6,
    DV_INC_ODD    = 7,
    DV_INC_IDX    = 8,
    DV_PACK       = 9,
    DV_HALT       = 10,
};

__declspec(noinline)
int vm_dual_counter_loop_target(int x) {
    int limit  = 0;
    int idx    = 0;
    int evens  = 0;
    int odds   = 0;
    int result = 0;
    int pc     = DV_INIT;

    while (1) {
        if (pc == DV_INIT) {
            pc = DV_LOAD_LIMIT;
        } else if (pc == DV_LOAD_LIMIT) {
            limit = x & 0xF;
            pc = DV_INIT_CTRS;
        } else if (pc == DV_INIT_CTRS) {
            evens = 0;
            odds = 0;
            pc = DV_INIT_IDX;
        } else if (pc == DV_INIT_IDX) {
            idx = 0;
            pc = DV_CHECK;
        } else if (pc == DV_CHECK) {
            pc = (idx < limit) ? DV_TEST_PAR : DV_PACK;
        } else if (pc == DV_TEST_PAR) {
            pc = ((idx & 1) == 0) ? DV_INC_EVEN : DV_INC_ODD;
        } else if (pc == DV_INC_EVEN) {
            evens = evens + 1;
            pc = DV_INC_IDX;
        } else if (pc == DV_INC_ODD) {
            odds = odds + 1;
            pc = DV_INC_IDX;
        } else if (pc == DV_INC_IDX) {
            idx = idx + 1;
            pc = DV_CHECK;
        } else if (pc == DV_PACK) {
            result = evens * 100 + odds;
            pc = DV_HALT;
        } else if (pc == DV_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dual_counter_loop(10)=%d vm_dual_counter_loop(15)=%d\n",
           vm_dual_counter_loop_target(10), vm_dual_counter_loop_target(15));
    return 0;
}
