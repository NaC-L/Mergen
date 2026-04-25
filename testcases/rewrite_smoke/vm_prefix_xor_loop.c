/* PC-state VM that fills a stack array and computes an in-place cumulative
 * XOR; returns the last element.
 * Lift target: vm_prefix_xor_loop_target.
 * Goal: cover an in-place array transform driven by XOR rather than ADD;
 * distinct from vm_prefix_sum_loop (additive prefix).  Trip count is
 * symbolic from the high nibble of x so the lifter cannot fully unroll.
 */
#include <stdio.h>

enum PxVmPc {
    PX_LOAD       = 0,
    PX_INIT_FILL  = 1,
    PX_FILL_CHECK = 2,
    PX_FILL_BODY  = 3,
    PX_FILL_INC   = 4,
    PX_INIT_SCAN  = 5,
    PX_SCAN_CHECK = 6,
    PX_SCAN_BODY  = 7,
    PX_SCAN_INC   = 8,
    PX_TAIL       = 9,
    PX_HALT       = 10,
};

__declspec(noinline)
int vm_prefix_xor_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int prev  = 0;
    int cur   = 0;
    int shift = 0;
    int result = 0;
    int pc    = PX_LOAD;

    while (1) {
        if (pc == PX_LOAD) {
            limit = (x & 7) + 1;
            pc = PX_INIT_FILL;
        } else if (pc == PX_INIT_FILL) {
            idx = 0;
            pc = PX_FILL_CHECK;
        } else if (pc == PX_FILL_CHECK) {
            pc = (idx < limit) ? PX_FILL_BODY : PX_INIT_SCAN;
        } else if (pc == PX_FILL_BODY) {
            shift = idx * 4;
            data[idx] = (x >> shift) & 0xF;
            pc = PX_FILL_INC;
        } else if (pc == PX_FILL_INC) {
            idx = idx + 1;
            pc = PX_FILL_CHECK;
        } else if (pc == PX_INIT_SCAN) {
            idx = 1;
            pc = PX_SCAN_CHECK;
        } else if (pc == PX_SCAN_CHECK) {
            pc = (idx < limit) ? PX_SCAN_BODY : PX_TAIL;
        } else if (pc == PX_SCAN_BODY) {
            prev = data[idx - 1];
            cur = data[idx];
            data[idx] = prev ^ cur;
            pc = PX_SCAN_INC;
        } else if (pc == PX_SCAN_INC) {
            idx = idx + 1;
            pc = PX_SCAN_CHECK;
        } else if (pc == PX_TAIL) {
            result = data[limit - 1];
            pc = PX_HALT;
        } else if (pc == PX_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_prefix_xor_loop(0x71234567)=%d vm_prefix_xor_loop(0xFFFFFFFF)=%d\n",
           vm_prefix_xor_loop_target(0x71234567), vm_prefix_xor_loop_target((int)0xFFFFFFFFu));
    return 0;
}
