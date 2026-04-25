/* PC-state VM that finds the INDEX of the max element in a symbolic-content
 * stack array.
 * Lift target: vm_argmax_loop_target.
 * Goal: cover a comparison-driven loop that tracks TWO co-related state vars
 * (current best value AND its index) where both update together when the
 * predicate is true.  Distinct from vm_minarray_loop (only tracks value, not
 * index).  Initial values come from data[0]/idx=0 written on the entry path
 * to keep the lifter's pseudo-stack promotion happy.
 */
#include <stdio.h>

enum AmVmPc {
    AM_LOAD       = 0,
    AM_INIT_FILL  = 1,
    AM_FILL_CHECK = 2,
    AM_FILL_BODY  = 3,
    AM_FILL_INC   = 4,
    AM_INIT_BEST  = 5,
    AM_SCAN_CHECK = 6,
    AM_SCAN_LOAD  = 7,
    AM_SCAN_TEST  = 8,
    AM_SCAN_UPD   = 9,
    AM_SCAN_INC   = 10,
    AM_HALT       = 11,
};

__declspec(noinline)
int vm_argmax_loop_target(int x) {
    int data[8];
    int limit  = 0;
    int idx    = 0;
    int best   = 0;
    int best_i = 0;
    int elt    = 0;
    int pc     = AM_LOAD;

    while (1) {
        if (pc == AM_LOAD) {
            limit = (x & 7) + 1;
            pc = AM_INIT_FILL;
        } else if (pc == AM_INIT_FILL) {
            idx = 0;
            pc = AM_FILL_CHECK;
        } else if (pc == AM_FILL_CHECK) {
            pc = (idx < limit) ? AM_FILL_BODY : AM_INIT_BEST;
        } else if (pc == AM_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x35)) & 0xFF;
            pc = AM_FILL_INC;
        } else if (pc == AM_FILL_INC) {
            idx = idx + 1;
            pc = AM_FILL_CHECK;
        } else if (pc == AM_INIT_BEST) {
            best = data[0];
            best_i = 0;
            idx = 1;
            pc = AM_SCAN_CHECK;
        } else if (pc == AM_SCAN_CHECK) {
            pc = (idx < limit) ? AM_SCAN_LOAD : AM_HALT;
        } else if (pc == AM_SCAN_LOAD) {
            elt = data[idx];
            pc = AM_SCAN_TEST;
        } else if (pc == AM_SCAN_TEST) {
            pc = (elt > best) ? AM_SCAN_UPD : AM_SCAN_INC;
        } else if (pc == AM_SCAN_UPD) {
            best = elt;
            best_i = idx;
            pc = AM_SCAN_INC;
        } else if (pc == AM_SCAN_INC) {
            idx = idx + 1;
            pc = AM_SCAN_CHECK;
        } else if (pc == AM_HALT) {
            return best_i;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_argmax_loop(0x37)=%d vm_argmax_loop(0xFEDC)=%d\n",
           vm_argmax_loop_target(0x37), vm_argmax_loop_target(0xFEDC));
    return 0;
}
