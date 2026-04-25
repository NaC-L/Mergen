/* PC-state VM that fills a stack array and then walks it computing an
 * in-place running prefix sum.
 * Lift target: vm_prefix_sum_loop_target.
 * Goal: cover a two-phase VM where the second loop *writes back* into the
 * stack array each iteration (data[i] += data[i-1]).  Distinct from
 * vm_minarray_loop where the second pass only reads.
 */
#include <stdio.h>

enum PsVmPc {
    PS_LOAD       = 0,
    PS_INIT_FILL  = 1,
    PS_FILL_CHECK = 2,
    PS_FILL_BODY  = 3,
    PS_FILL_INC   = 4,
    PS_INIT_SCAN  = 5,
    PS_SCAN_CHECK = 6,
    PS_SCAN_LOAD  = 7,
    PS_SCAN_STORE = 8,
    PS_SCAN_INC   = 9,
    PS_TAIL       = 10,
    PS_HALT       = 11,
};

__declspec(noinline)
int vm_prefix_sum_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int prev  = 0;
    int cur   = 0;
    int sum   = 0;
    int pc    = PS_LOAD;

    while (1) {
        if (pc == PS_LOAD) {
            limit = (x & 7) + 1;
            pc = PS_INIT_FILL;
        } else if (pc == PS_INIT_FILL) {
            idx = 0;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_FILL_CHECK) {
            pc = (idx < limit) ? PS_FILL_BODY : PS_INIT_SCAN;
        } else if (pc == PS_FILL_BODY) {
            data[idx] = (x + idx) & 0xF;
            pc = PS_FILL_INC;
        } else if (pc == PS_FILL_INC) {
            idx = idx + 1;
            pc = PS_FILL_CHECK;
        } else if (pc == PS_INIT_SCAN) {
            idx = 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_SCAN_CHECK) {
            pc = (idx < limit) ? PS_SCAN_LOAD : PS_TAIL;
        } else if (pc == PS_SCAN_LOAD) {
            prev = data[idx - 1];
            cur = data[idx];
            pc = PS_SCAN_STORE;
        } else if (pc == PS_SCAN_STORE) {
            data[idx] = prev + cur;
            pc = PS_SCAN_INC;
        } else if (pc == PS_SCAN_INC) {
            idx = idx + 1;
            pc = PS_SCAN_CHECK;
        } else if (pc == PS_TAIL) {
            sum = data[limit - 1];
            pc = PS_HALT;
        } else if (pc == PS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_prefix_sum_loop(0x55)=%d vm_prefix_sum_loop(0x1234)=%d\n",
           vm_prefix_sum_loop_target(0x55), vm_prefix_sum_loop_target(0x1234));
    return 0;
}
