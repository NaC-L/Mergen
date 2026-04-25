/* PC-state VM that copies a stack array into a second stack array in
 * REVERSED index order, then returns the first and last elements packed.
 * Lift target: vm_reverse_array_loop_target.
 * Goal: cover an indexed-load-with-derived-index pattern (buf[7-i]) inside
 * a VM dispatcher.  Avoids the in-place swap that trips BB-budget-503.
 */
#include <stdio.h>

enum RaVmPc {
    RA_LOAD       = 0,
    RA_INIT_FILL  = 1,
    RA_FILL_CHECK = 2,
    RA_FILL_BODY  = 3,
    RA_FILL_INC   = 4,
    RA_INIT_REV   = 5,
    RA_REV_CHECK  = 6,
    RA_REV_BODY   = 7,
    RA_REV_INC    = 8,
    RA_PACK       = 9,
    RA_HALT       = 10,
};

__declspec(noinline)
int vm_reverse_array_loop_target(int x) {
    int buf[8];
    int buf2[8];
    int idx    = 0;
    int result = 0;
    int seed   = 0;
    int pc     = RA_LOAD;

    while (1) {
        if (pc == RA_LOAD) {
            seed = x & 0xF;
            pc = RA_INIT_FILL;
        } else if (pc == RA_INIT_FILL) {
            idx = 0;
            pc = RA_FILL_CHECK;
        } else if (pc == RA_FILL_CHECK) {
            pc = (idx < 8) ? RA_FILL_BODY : RA_INIT_REV;
        } else if (pc == RA_FILL_BODY) {
            buf[idx] = (idx + seed) & 0xF;
            pc = RA_FILL_INC;
        } else if (pc == RA_FILL_INC) {
            idx = idx + 1;
            pc = RA_FILL_CHECK;
        } else if (pc == RA_INIT_REV) {
            idx = 0;
            pc = RA_REV_CHECK;
        } else if (pc == RA_REV_CHECK) {
            pc = (idx < 8) ? RA_REV_BODY : RA_PACK;
        } else if (pc == RA_REV_BODY) {
            buf2[idx] = buf[7 - idx];
            pc = RA_REV_INC;
        } else if (pc == RA_REV_INC) {
            idx = idx + 1;
            pc = RA_REV_CHECK;
        } else if (pc == RA_PACK) {
            result = (buf2[0] & 0xF) | ((buf2[7] & 0xF) << 4);
            pc = RA_HALT;
        } else if (pc == RA_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_reverse_array_loop(0x5)=%d vm_reverse_array_loop(0xCAFE)=%d\n",
           vm_reverse_array_loop_target(0x5),
           vm_reverse_array_loop_target(0xCAFE));
    return 0;
}
