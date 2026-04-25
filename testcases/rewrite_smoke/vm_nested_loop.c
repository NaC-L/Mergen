/* PC-state VM with two nested counted loops, both encoded in interpreter state.
 * Lift target: vm_nested_loop_target.
 * Goal: stress loop generalization by keeping the outer and inner loops as
 * distinct PC cycles rather than native control flow.  Both bounds are
 * symbolic (a = x & 3, b = (x>>2) & 3), and the inner body computes
 * acc += i + j across the full grid.
 */
#include <stdio.h>

enum NestedVmPc {
    NV_INIT        = 0,
    NV_OUTER_CHECK = 1,
    NV_INNER_INIT  = 2,
    NV_INNER_CHECK = 3,
    NV_INNER_BODY  = 4,
    NV_INNER_INC   = 5,
    NV_OUTER_INC   = 6,
    NV_HALT        = 7,
};

__declspec(noinline)
int vm_nested_loop_target(int x) {
    int a   = x & 3;
    int b   = (x >> 2) & 3;
    int i   = 0;
    int j   = 0;
    int acc = 0;
    int pc  = NV_INIT;

    while (1) {
        if (pc == NV_INIT) {
            i = 0;
            acc = 0;
            pc = NV_OUTER_CHECK;
        } else if (pc == NV_OUTER_CHECK) {
            pc = (i < a) ? NV_INNER_INIT : NV_HALT;
        } else if (pc == NV_INNER_INIT) {
            j = 0;
            pc = NV_INNER_CHECK;
        } else if (pc == NV_INNER_CHECK) {
            pc = (j < b) ? NV_INNER_BODY : NV_OUTER_INC;
        } else if (pc == NV_INNER_BODY) {
            acc = acc + i + j;
            pc = NV_INNER_INC;
        } else if (pc == NV_INNER_INC) {
            j = j + 1;
            pc = NV_INNER_CHECK;
        } else if (pc == NV_OUTER_INC) {
            i = i + 1;
            pc = NV_OUTER_CHECK;
        } else if (pc == NV_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_nested_loop(15)=%d vm_nested_loop(11)=%d\n",
           vm_nested_loop_target(15), vm_nested_loop_target(11));
    return 0;
}
