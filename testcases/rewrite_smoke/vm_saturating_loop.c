/* PC-state VM running a counted sum loop with saturation clamp.
 * Lift target: vm_saturating_loop_target.
 * Goal: cover a loop body that performs an add followed by a value-clamp
 * (select on overflow), distinct from the pure additive sum loops which
 * grow unbounded.  Trip count n = x & 0xFF spans the full clamp boundary.
 */
#include <stdio.h>

enum SatVmPc {
    ST_LOAD     = 0,
    ST_INIT     = 1,
    ST_CHECK    = 2,
    ST_BODY_ADD = 3,
    ST_BODY_CLAMP = 4,
    ST_BODY_INC = 5,
    ST_HALT     = 6,
};

__declspec(noinline)
int vm_saturating_loop_target(int x) {
    int n   = 0;
    int i   = 0;
    int sum = 0;
    int pc  = ST_LOAD;

    while (1) {
        if (pc == ST_LOAD) {
            n = x & 0xFF;
            i = 0;
            sum = 0;
            pc = ST_INIT;
        } else if (pc == ST_INIT) {
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY_ADD : ST_HALT;
        } else if (pc == ST_BODY_ADD) {
            sum = sum + i;
            pc = ST_BODY_CLAMP;
        } else if (pc == ST_BODY_CLAMP) {
            if (sum > 100) {
                sum = 100;
            }
            pc = ST_BODY_INC;
        } else if (pc == ST_BODY_INC) {
            i = i + 1;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_saturating_loop(10)=%d vm_saturating_loop(20)=%d\n",
           vm_saturating_loop_target(10), vm_saturating_loop_target(20));
    return 0;
}
