/* PC-state VM doing 8-bit left rotation by a symbolic count.
 * Lift target: vm_rotate_loop_target.
 * Goal: cover a bitwise loop whose body uses both shl and lshr to wrap bits
 * around (rotation, not just shift).  Both value and rotation count are
 * symbolic.  Init dispatcher state pre-writes the loop variables.
 */
#include <stdio.h>

enum RotVmPc {
    RT_LOAD       = 0,
    RT_CHECK      = 1,
    RT_BODY_HI    = 2,
    RT_BODY_LO    = 3,
    RT_BODY_OR    = 4,
    RT_BODY_MASK  = 5,
    RT_BODY_DEC   = 6,
    RT_HALT       = 7,
};

__declspec(noinline)
int vm_rotate_loop_target(int x) {
    int val   = 0;
    int n     = 0;
    int hi    = 0;
    int lo    = 0;
    int pc    = RT_LOAD;

    while (1) {
        if (pc == RT_LOAD) {
            val = x & 0xFF;
            n = (x >> 8) & 7;
            pc = RT_CHECK;
        } else if (pc == RT_CHECK) {
            pc = (n > 0) ? RT_BODY_HI : RT_HALT;
        } else if (pc == RT_BODY_HI) {
            hi = (int)((unsigned)val >> 7);
            pc = RT_BODY_LO;
        } else if (pc == RT_BODY_LO) {
            lo = val << 1;
            pc = RT_BODY_OR;
        } else if (pc == RT_BODY_OR) {
            val = lo | hi;
            pc = RT_BODY_MASK;
        } else if (pc == RT_BODY_MASK) {
            val = val & 0xFF;
            pc = RT_BODY_DEC;
        } else if (pc == RT_BODY_DEC) {
            n = n - 1;
            pc = RT_CHECK;
        } else if (pc == RT_HALT) {
            return val;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_rotate_loop(0x755)=%d vm_rotate_loop(0x70F)=%d\n",
           vm_rotate_loop_target(0x755), vm_rotate_loop_target(0x70F));
    return 0;
}
