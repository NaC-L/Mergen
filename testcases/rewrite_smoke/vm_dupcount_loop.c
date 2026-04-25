/* PC-state VM that counts adjacent equal nibbles extracted from x.
 * Lift target: vm_dupcount_loop_target.
 * Goal: cover a loop body that loads TWO stack-array elements at adjacent
 * indices (data[i-1] and data[i]) and conditionally increments a counter
 * on equality.  Distinct from vm_runlength_loop (compares previous *bit*,
 * here previous *array element*).
 */
#include <stdio.h>

enum DcVmPc {
    DC_LOAD       = 0,
    DC_INIT_FILL  = 1,
    DC_FILL_CHECK = 2,
    DC_FILL_BODY  = 3,
    DC_FILL_INC   = 4,
    DC_INIT_SCAN  = 5,
    DC_SCAN_CHECK = 6,
    DC_SCAN_LOAD  = 7,
    DC_SCAN_TEST  = 8,
    DC_SCAN_INC_C = 9,
    DC_SCAN_INC_I = 10,
    DC_HALT       = 11,
};

__declspec(noinline)
int vm_dupcount_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int count = 0;
    int prev  = 0;
    int cur   = 0;
    int pc    = DC_LOAD;

    while (1) {
        if (pc == DC_LOAD) {
            limit = (x & 7) + 1;
            count = 0;
            pc = DC_INIT_FILL;
        } else if (pc == DC_INIT_FILL) {
            idx = 0;
            pc = DC_FILL_CHECK;
        } else if (pc == DC_FILL_CHECK) {
            pc = (idx < limit) ? DC_FILL_BODY : DC_INIT_SCAN;
        } else if (pc == DC_FILL_BODY) {
            data[idx] = (x >> (idx * 4)) & 0xF;
            pc = DC_FILL_INC;
        } else if (pc == DC_FILL_INC) {
            idx = idx + 1;
            pc = DC_FILL_CHECK;
        } else if (pc == DC_INIT_SCAN) {
            idx = 1;
            pc = DC_SCAN_CHECK;
        } else if (pc == DC_SCAN_CHECK) {
            pc = (idx < limit) ? DC_SCAN_LOAD : DC_HALT;
        } else if (pc == DC_SCAN_LOAD) {
            prev = data[idx - 1];
            cur = data[idx];
            pc = DC_SCAN_TEST;
        } else if (pc == DC_SCAN_TEST) {
            pc = (cur == prev) ? DC_SCAN_INC_C : DC_SCAN_INC_I;
        } else if (pc == DC_SCAN_INC_C) {
            count = count + 1;
            pc = DC_SCAN_INC_I;
        } else if (pc == DC_SCAN_INC_I) {
            idx = idx + 1;
            pc = DC_SCAN_CHECK;
        } else if (pc == DC_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dupcount_loop(0x77777777)=%d vm_dupcount_loop(0x11223344)=%d\n",
           vm_dupcount_loop_target(0x77777777), vm_dupcount_loop_target(0x11223344));
    return 0;
}
