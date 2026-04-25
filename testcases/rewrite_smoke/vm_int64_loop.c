/* PC-state VM whose loop body uses 64-bit arithmetic.
 * Lift target: vm_int64_loop_target.
 * Goal: cover a multiplicative recurrence over int64 (acc = acc * 31 + i)
 * inside a VM dispatcher with the result truncated to int.  Tests the
 * lifter's handling of 64-bit mul/add inside loop bodies.
 */
#include <stdio.h>

enum I6VmPc {
    I6_LOAD       = 0,
    I6_INIT       = 1,
    I6_CHECK      = 2,
    I6_BODY_MUL   = 3,
    I6_BODY_ADD   = 4,
    I6_BODY_INC   = 5,
    I6_HALT       = 6,
};

__declspec(noinline)
int vm_int64_loop_target(int x) {
    long long acc = 0;
    int limit = 0;
    int idx   = 0;
    int pc    = I6_LOAD;

    while (1) {
        if (pc == I6_LOAD) {
            limit = (x & 7) + 1;
            acc = 0;
            pc = I6_INIT;
        } else if (pc == I6_INIT) {
            idx = 0;
            pc = I6_CHECK;
        } else if (pc == I6_CHECK) {
            pc = (idx < limit) ? I6_BODY_MUL : I6_HALT;
        } else if (pc == I6_BODY_MUL) {
            acc = acc * 31LL;
            pc = I6_BODY_ADD;
        } else if (pc == I6_BODY_ADD) {
            acc = acc + (long long)idx;
            pc = I6_BODY_INC;
        } else if (pc == I6_BODY_INC) {
            idx = idx + 1;
            pc = I6_CHECK;
        } else if (pc == I6_HALT) {
            return (int)(acc & 0xFFFFFFFFLL);
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_int64_loop(0xCAFE)=%d vm_int64_loop(0x12345)=%d\n",
           vm_int64_loop_target(0xCAFE),
           vm_int64_loop_target(0x12345));
    return 0;
}
