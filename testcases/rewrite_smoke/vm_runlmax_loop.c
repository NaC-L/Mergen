/* PC-state VM that finds the length of the longest run of consecutive 1-bits
 * in the low 16 bits of x.
 * Lift target: vm_runlmax_loop_target.
 * Goal: cover a loop body that maintains TWO state vars (current run length
 * and max so far) using the always-write recipe:
 *   cur = (cur + 1) * bit       // 0 resets, 1 extends
 *   max = (cur > max) ? cur : max  // always written
 */
#include <stdio.h>

enum RmVmPc {
    RM_LOAD       = 0,
    RM_INIT       = 1,
    RM_CHECK      = 2,
    RM_BODY_BIT   = 3,
    RM_BODY_CUR   = 4,
    RM_BODY_MAX   = 5,
    RM_BODY_INC   = 6,
    RM_HALT       = 7,
};

__declspec(noinline)
int vm_runlmax_loop_target(int x) {
    int idx   = 0;
    int cur   = 0;
    int mx    = 0;
    int bit   = 0;
    int next  = 0;
    int pc    = RM_LOAD;

    while (1) {
        if (pc == RM_LOAD) {
            idx = 0;
            cur = 0;
            mx = 0;
            pc = RM_INIT;
        } else if (pc == RM_INIT) {
            pc = RM_CHECK;
        } else if (pc == RM_CHECK) {
            pc = (idx < 16) ? RM_BODY_BIT : RM_HALT;
        } else if (pc == RM_BODY_BIT) {
            bit = (x >> idx) & 1;
            pc = RM_BODY_CUR;
        } else if (pc == RM_BODY_CUR) {
            cur = (cur + 1) * bit;
            pc = RM_BODY_MAX;
        } else if (pc == RM_BODY_MAX) {
            next = (cur > mx) ? cur : mx;
            mx = next;
            pc = RM_BODY_INC;
        } else if (pc == RM_BODY_INC) {
            idx = idx + 1;
            pc = RM_CHECK;
        } else if (pc == RM_HALT) {
            return mx;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_runlmax_loop(0xFFFF)=%d vm_runlmax_loop(0x1F8)=%d\n",
           vm_runlmax_loop_target(0xFFFF), vm_runlmax_loop_target(0x1F8));
    return 0;
}
