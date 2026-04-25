/* PC-state VM that fills a stack array from a symbolic input then scans it
 * for the minimum byte value.
 * Lift target: vm_minarray_loop_target.
 * Goal: cover a comparison-driven update loop (running minimum) over an
 * array whose contents depend on x, with the trip count also derived from x
 * so the lifter cannot fully unroll the search.
 */
#include <stdio.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT_IDX   = 1,
    MA_FILL_CHECK = 2,
    MA_FILL_BODY  = 3,
    MA_FILL_INC   = 4,
    MA_INIT_MIN   = 5,
    MA_SCAN_CHECK = 6,
    MA_SCAN_LOAD  = 7,
    MA_SCAN_TEST  = 8,
    MA_SCAN_UPDATE = 9,
    MA_SCAN_INC   = 10,
    MA_HALT       = 11,
};

__declspec(noinline)
int vm_minarray_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int elt   = 0;
    int best  = 0;
    int pc    = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            limit = (x & 7) + 1;
            pc = MA_INIT_IDX;
        } else if (pc == MA_INIT_IDX) {
            idx = 0;
            pc = MA_FILL_CHECK;
        } else if (pc == MA_FILL_CHECK) {
            pc = (idx < limit) ? MA_FILL_BODY : MA_INIT_MIN;
        } else if (pc == MA_FILL_BODY) {
            data[idx] = (x + idx * 13) & 0xFF;
            pc = MA_FILL_INC;
        } else if (pc == MA_FILL_INC) {
            idx = idx + 1;
            pc = MA_FILL_CHECK;
        } else if (pc == MA_INIT_MIN) {
            best = data[0];
            idx = 1;
            pc = MA_SCAN_CHECK;
        } else if (pc == MA_SCAN_CHECK) {
            pc = (idx < limit) ? MA_SCAN_LOAD : MA_HALT;
        } else if (pc == MA_SCAN_LOAD) {
            elt = data[idx];
            pc = MA_SCAN_TEST;
        } else if (pc == MA_SCAN_TEST) {
            pc = (elt < best) ? MA_SCAN_UPDATE : MA_SCAN_INC;
        } else if (pc == MA_SCAN_UPDATE) {
            best = elt;
            pc = MA_SCAN_INC;
        } else if (pc == MA_SCAN_INC) {
            idx = idx + 1;
            pc = MA_SCAN_CHECK;
        } else if (pc == MA_HALT) {
            return best;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_minarray_loop(0xFF)=%d vm_minarray_loop(0xABC)=%d\n",
           vm_minarray_loop_target(0xFF), vm_minarray_loop_target(0xABC));
    return 0;
}
