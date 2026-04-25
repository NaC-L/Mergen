/* PC-state VM running Brian Kernighan's popcount trick.
 * Lift target: vm_kernighan_loop_target.
 * Goal: cover a non-counted loop whose body uses v &= v - 1 to clear the
 * lowest set bit, terminating when v reaches zero.  Distinct from
 * vm_popcount_loop (which examines one bit per iteration via shift-and-and):
 * here the trip count equals the popcount itself, and each iteration
 * subtracts one then ANDs.
 */
#include <stdio.h>

enum KnVmPc {
    KN_LOAD       = 0,
    KN_INIT       = 1,
    KN_CHECK      = 2,
    KN_BODY_SUB   = 3,
    KN_BODY_AND   = 4,
    KN_BODY_INC   = 5,
    KN_HALT       = 6,
};

__declspec(noinline)
int vm_kernighan_loop_target(int x) {
    int v     = 0;
    int count = 0;
    int sub   = 0;
    int pc    = KN_LOAD;

    while (1) {
        if (pc == KN_LOAD) {
            v = x & 0xFFFF;
            count = 0;
            pc = KN_INIT;
        } else if (pc == KN_INIT) {
            pc = KN_CHECK;
        } else if (pc == KN_CHECK) {
            pc = (v != 0) ? KN_BODY_SUB : KN_HALT;
        } else if (pc == KN_BODY_SUB) {
            sub = v - 1;
            pc = KN_BODY_AND;
        } else if (pc == KN_BODY_AND) {
            v = v & sub;
            pc = KN_BODY_INC;
        } else if (pc == KN_BODY_INC) {
            count = count + 1;
            pc = KN_CHECK;
        } else if (pc == KN_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_kernighan_loop(0xFFFF)=%d vm_kernighan_loop(0x1234)=%d\n",
           vm_kernighan_loop_target(0xFFFF), vm_kernighan_loop_target(0x1234));
    return 0;
}
