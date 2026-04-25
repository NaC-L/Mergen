/* PC-state VM that finds the maximum sum of a 3-element sliding window
 * over a symbolic-content stack array.
 * Lift target: vm_window_loop_target.
 * Goal: cover a loop body that loads THREE adjacent stack-array elements
 * (data[i], data[i+1], data[i+2]) per iteration and updates a running max.
 * Distinct from vm_dupcount_loop (loads two elements) and vm_minarray_loop
 * (loads one).
 */
#include <stdio.h>

enum WnVmPc {
    WN_LOAD       = 0,
    WN_INIT_FILL  = 1,
    WN_FILL_CHECK = 2,
    WN_FILL_BODY  = 3,
    WN_FILL_INC   = 4,
    WN_INIT_SCAN  = 5,
    WN_SCAN_CHECK = 6,
    WN_SCAN_LOAD  = 7,
    WN_SCAN_SUM   = 8,
    WN_SCAN_MAX   = 9,
    WN_SCAN_INC   = 10,
    WN_HALT       = 11,
};

__declspec(noinline)
int vm_window_loop_target(int x) {
    int data[10];
    int limit = 0;
    int idx   = 0;
    int a     = 0;
    int b     = 0;
    int c     = 0;
    int s     = 0;
    int mx    = 0;
    int pc    = WN_LOAD;

    while (1) {
        if (pc == WN_LOAD) {
            limit = (x & 7) + 3;
            mx = 0;
            pc = WN_INIT_FILL;
        } else if (pc == WN_INIT_FILL) {
            idx = 0;
            pc = WN_FILL_CHECK;
        } else if (pc == WN_FILL_CHECK) {
            pc = (idx < limit) ? WN_FILL_BODY : WN_INIT_SCAN;
        } else if (pc == WN_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x37)) & 0xFF;
            pc = WN_FILL_INC;
        } else if (pc == WN_FILL_INC) {
            idx = idx + 1;
            pc = WN_FILL_CHECK;
        } else if (pc == WN_INIT_SCAN) {
            idx = 0;
            pc = WN_SCAN_CHECK;
        } else if (pc == WN_SCAN_CHECK) {
            pc = (idx <= limit - 3) ? WN_SCAN_LOAD : WN_HALT;
        } else if (pc == WN_SCAN_LOAD) {
            a = data[idx];
            b = data[idx + 1];
            c = data[idx + 2];
            pc = WN_SCAN_SUM;
        } else if (pc == WN_SCAN_SUM) {
            s = a + b + c;
            pc = WN_SCAN_MAX;
        } else if (pc == WN_SCAN_MAX) {
            mx = (s > mx) ? s : mx;
            pc = WN_SCAN_INC;
        } else if (pc == WN_SCAN_INC) {
            idx = idx + 1;
            pc = WN_SCAN_CHECK;
        } else if (pc == WN_HALT) {
            return mx;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_window_loop(0xFF)=%d vm_window_loop(0x1234)=%d\n",
           vm_window_loop_target(0xFF), vm_window_loop_target(0x1234));
    return 0;
}
