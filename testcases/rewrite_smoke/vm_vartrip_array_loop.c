/* PC-state VM with a 16-slot stack array and an INPUT-DERIVED trip
 * count (n = (x & 0xF) + 1, range 1..16).  Single fill+sum fused into
 * the loop body to keep the lifter's analysis budget within range while
 * still exercising a variable-trip stack-array loop.
 * Lift target: vm_vartrip_array_loop_target.
 *
 * Distinct from existing samples that fix the trip count to 8/16 and
 * unroll fully; here the lifter must keep a real loop body because the
 * trip count is not constant.
 */
#include <stdio.h>

enum VtVmPc {
    VT_LOAD       = 0,
    VT_INIT       = 1,
    VT_LOOP_CHECK = 2,
    VT_LOOP_BODY  = 3,
    VT_LOOP_INC   = 4,
    VT_HALT       = 5,
};

__declspec(noinline)
int vm_vartrip_array_loop_target(int x) {
    int buf[16];
    int idx     = 0;
    int sum     = 0;
    int n       = 0;
    int seed_hi = 0;
    int pc      = VT_LOAD;

    while (1) {
        if (pc == VT_LOAD) {
            n       = (x & 0xF) + 1;
            seed_hi = (int)((unsigned int)x >> 8);
            idx     = 0;
            sum     = 0;
            pc = VT_INIT;
        } else if (pc == VT_INIT) {
            idx = 0;
            pc = VT_LOOP_CHECK;
        } else if (pc == VT_LOOP_CHECK) {
            pc = (idx < n) ? VT_LOOP_BODY : VT_HALT;
        } else if (pc == VT_LOOP_BODY) {
            buf[idx] = idx ^ seed_hi;
            sum = sum + buf[idx];
            pc = VT_LOOP_INC;
        } else if (pc == VT_LOOP_INC) {
            idx = idx + 1;
            pc = VT_LOOP_CHECK;
        } else if (pc == VT_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_vartrip(0xF)=%d vm_vartrip(0xCAFE)=%d\n",
           vm_vartrip_array_loop_target(0xF),
           vm_vartrip_array_loop_target(0xCAFE));
    return 0;
}
