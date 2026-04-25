/* PC-state VM running a geometric (log2-style) doubling loop.
 * Lift target: vm_geometric_loop_target.
 * Goal: cover a loop where the induction variable grows multiplicatively
 * (r *= 2) while a counter grows linearly, terminating when r reaches a
 * symbolic target.  Different recurrence shape from the additive sum
 * loops and the multiplicative factorial loop (where the loop bound is
 * symbolic, not the value).
 */
#include <stdio.h>

enum GeoVmPc {
    GE_LOAD     = 0,
    GE_INIT     = 1,
    GE_CHECK    = 2,
    GE_BODY_DBL = 3,
    GE_BODY_INC = 4,
    GE_HALT     = 5,
};

__declspec(noinline)
int vm_geometric_loop_target(int x) {
    int target = 0;
    int r      = 0;
    int count  = 0;
    int pc     = GE_LOAD;

    while (1) {
        if (pc == GE_LOAD) {
            target = (x & 0xFF) | 1;
            r = 1;
            count = 0;
            pc = GE_INIT;
        } else if (pc == GE_INIT) {
            pc = GE_CHECK;
        } else if (pc == GE_CHECK) {
            pc = (r < target) ? GE_BODY_DBL : GE_HALT;
        } else if (pc == GE_BODY_DBL) {
            r = r * 2;
            pc = GE_BODY_INC;
        } else if (pc == GE_BODY_INC) {
            count = count + 1;
            pc = GE_CHECK;
        } else if (pc == GE_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_geometric_loop(15)=%d vm_geometric_loop(128)=%d\n",
           vm_geometric_loop_target(15), vm_geometric_loop_target(128));
    return 0;
}
