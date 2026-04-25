/* PC-state VM running the Euclidean GCD algorithm.
 * Lift target: vm_gcd_loop_target.
 * Goal: cover a non-counted loop driven by a modulo recurrence inside the VM
 * body.  Inputs a = (x & 0xF) + 1 and b = ((x >> 4) & 0xF) + 1 keep both
 * operands in [1, 16] and symbolic, so the lifter cannot fold the loop.
 */
#include <stdio.h>

enum GcdVmPc {
    GV_INIT     = 0,
    GV_LOAD_A   = 1,
    GV_LOAD_B   = 2,
    GV_CHECK    = 3,
    GV_BODY_MOD = 4,
    GV_BODY_SWAP= 5,
    GV_HALT     = 6,
};

__declspec(noinline)
int vm_gcd_loop_target(int x) {
    int a    = 0;
    int b    = 0;
    int tmp  = 0;
    int pc   = GV_INIT;

    while (1) {
        if (pc == GV_INIT) {
            pc = GV_LOAD_A;
        } else if (pc == GV_LOAD_A) {
            a = (x & 0xF) + 1;
            pc = GV_LOAD_B;
        } else if (pc == GV_LOAD_B) {
            b = ((x >> 4) & 0xF) + 1;
            pc = GV_CHECK;
        } else if (pc == GV_CHECK) {
            pc = (b != 0) ? GV_BODY_MOD : GV_HALT;
        } else if (pc == GV_BODY_MOD) {
            tmp = a % b;
            pc = GV_BODY_SWAP;
        } else if (pc == GV_BODY_SWAP) {
            a = b;
            b = tmp;
            pc = GV_CHECK;
        } else if (pc == GV_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_gcd_loop(0x66)=%d vm_gcd_loop(0x57)=%d\n",
           vm_gcd_loop_target(0x66), vm_gcd_loop_target(0x57));
    return 0;
}
