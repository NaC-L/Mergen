/* PC-state VM doing a linear search through a stack-resident table.
 * Lift target: vm_search_loop_target.
 * Goal: cover a loop whose body reads from a stack array and exits early
 * via a state transition when a match is found.  The target is symbolic
 * (target = (x & 0xF) + 1) so half the inputs hit, half miss; the lifter
 * must keep both the loop and the early-out branch.
 */
#include <stdio.h>

enum SearchVmPc {
    SR_INIT       = 0,
    SR_INIT_DATA  = 1,
    SR_LOAD_TGT   = 2,
    SR_INIT_IDX   = 3,
    SR_CHECK_END  = 4,
    SR_LOAD_ELT   = 5,
    SR_TEST_EQ    = 6,
    SR_INC_IDX    = 7,
    SR_FOUND      = 8,
    SR_HALT       = 9,
};

__declspec(noinline)
int vm_search_loop_target(int x) {
    int data[8];
    int target = 0;
    int idx    = 0;
    int elt    = 0;
    int result = 0;
    int pc     = SR_INIT;

    while (1) {
        if (pc == SR_INIT) {
            pc = SR_INIT_DATA;
        } else if (pc == SR_INIT_DATA) {
            data[0] = 3;  data[1] = 7;  data[2] = 11; data[3] = 13;
            data[4] = 17; data[5] = 19; data[6] = 23; data[7] = 29;
            pc = SR_LOAD_TGT;
        } else if (pc == SR_LOAD_TGT) {
            target = (x & 0xF) + 1;
            pc = SR_INIT_IDX;
        } else if (pc == SR_INIT_IDX) {
            idx = 0;
            pc = SR_CHECK_END;
        } else if (pc == SR_CHECK_END) {
            if (idx >= 8) { result = 8; pc = SR_HALT; }
            else { pc = SR_LOAD_ELT; }
        } else if (pc == SR_LOAD_ELT) {
            elt = data[idx];
            pc = SR_TEST_EQ;
        } else if (pc == SR_TEST_EQ) {
            pc = (elt == target) ? SR_FOUND : SR_INC_IDX;
        } else if (pc == SR_INC_IDX) {
            idx = idx + 1;
            pc = SR_CHECK_END;
        } else if (pc == SR_FOUND) {
            result = idx;
            pc = SR_HALT;
        } else if (pc == SR_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_search_loop(2)=%d vm_search_loop(15)=%d\n",
           vm_search_loop_target(2), vm_search_loop_target(15));
    return 0;
}
