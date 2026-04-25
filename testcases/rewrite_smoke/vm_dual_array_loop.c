/* PC-state VM that allocates TWO independent int[8] stack arrays at the
 * same time, fills each with a different formula, and accumulates a
 * cross-product sum_{i}(a[i] * b[7-i]).
 * Lift target: vm_dual_array_loop_target.
 * Goal: cover two simultaneous stack arrays in flight (distinct stack
 * slots, independent fill loops, paired access in a third loop), as
 * opposed to existing samples that operate on a single stack array.
 */
#include <stdio.h>

enum DaVmPc {
    DA_LOAD       = 0,
    DA_INIT_FILL  = 1,
    DA_FILL_CHECK = 2,
    DA_FILL_BODY  = 3,
    DA_FILL_INC   = 4,
    DA_INIT_PROD  = 5,
    DA_PROD_CHECK = 6,
    DA_PROD_BODY  = 7,
    DA_PROD_INC   = 8,
    DA_HALT       = 9,
};

__declspec(noinline)
int vm_dual_array_loop_target(int x) {
    int a[8];
    int b[8];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = DA_LOAD;

    while (1) {
        if (pc == DA_LOAD) {
            seed = x;
            pc = DA_INIT_FILL;
        } else if (pc == DA_INIT_FILL) {
            idx = 0;
            pc = DA_FILL_CHECK;
        } else if (pc == DA_FILL_CHECK) {
            pc = (idx < 8) ? DA_FILL_BODY : DA_INIT_PROD;
        } else if (pc == DA_FILL_BODY) {
            a[idx] = seed + idx;
            b[idx] = seed * (idx + 1);
            pc = DA_FILL_INC;
        } else if (pc == DA_FILL_INC) {
            idx = idx + 1;
            pc = DA_FILL_CHECK;
        } else if (pc == DA_INIT_PROD) {
            idx = 0;
            pc = DA_PROD_CHECK;
        } else if (pc == DA_PROD_CHECK) {
            pc = (idx < 8) ? DA_PROD_BODY : DA_HALT;
        } else if (pc == DA_PROD_BODY) {
            sum = sum + a[idx] * b[7 - idx];
            pc = DA_PROD_INC;
        } else if (pc == DA_PROD_INC) {
            idx = idx + 1;
            pc = DA_PROD_CHECK;
        } else if (pc == DA_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_dual_array_loop(10)=%d vm_dual_array_loop(100)=%d\n",
           vm_dual_array_loop_target(10),
           vm_dual_array_loop_target(100));
    return 0;
}
