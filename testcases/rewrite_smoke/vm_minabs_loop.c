/* PC-state VM that tracks the minimum abs() distance from i*13 to a
 * symbolic target across a counted loop.
 * Lift target: vm_minabs_loop_target.
 * Goal: cover a comparison-driven update loop where the predicate is
 * computed via an imported intrinsic call (abs).  Distinct from
 * vm_imported_abs_loop (sums abs values) and vm_minarray_loop (compares
 * raw stack-array elements without a call).
 */
#include <stdio.h>
#include <stdlib.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT       = 1,
    MA_CHECK      = 2,
    MA_BODY_DELTA = 3,
    MA_BODY_CALL  = 4,
    MA_BODY_TEST  = 5,
    MA_BODY_INC   = 6,
    MA_HALT       = 7,
};

__declspec(noinline)
int vm_minabs_loop_target(int x) {
    int limit  = 0;
    int idx    = 0;
    int best   = 0;
    int target = 0;
    int delta  = 0;
    int abs_r  = 0;
    int pc     = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            limit = (x & 0xF) + 1;
            target = ((x >> 4) & 0xFF) - 128;
            best = 256;
            pc = MA_INIT;
        } else if (pc == MA_INIT) {
            idx = 0;
            pc = MA_CHECK;
        } else if (pc == MA_CHECK) {
            pc = (idx < limit) ? MA_BODY_DELTA : MA_HALT;
        } else if (pc == MA_BODY_DELTA) {
            delta = (idx * 13) - target;
            pc = MA_BODY_CALL;
        } else if (pc == MA_BODY_CALL) {
            abs_r = abs(delta);
            pc = MA_BODY_TEST;
        } else if (pc == MA_BODY_TEST) {
            best = (abs_r < best) ? abs_r : best;
            pc = MA_BODY_INC;
        } else if (pc == MA_BODY_INC) {
            idx = idx + 1;
            pc = MA_CHECK;
        } else if (pc == MA_HALT) {
            return best;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_minabs_loop(0xABC)=%d vm_minabs_loop(0xFFFF)=%d\n",
           vm_minabs_loop_target(0xABC), vm_minabs_loop_target(0xFFFF));
    return 0;
}
