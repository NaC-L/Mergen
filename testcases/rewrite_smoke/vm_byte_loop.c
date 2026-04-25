/* PC-state VM with explicit unsigned char (i8) arithmetic recurrence.
 * Lift target: vm_byte_loop_target.
 * Goal: cover narrower-type (i8) arithmetic inside a VM dispatcher.
 * state = state * 13 + 5 (mod 256), iterated symbolic times.
 * Distinct from existing i32 recurrences and the int64 family.
 */
#include <stdio.h>

enum BvVmPc {
    BV_LOAD       = 0,
    BV_INIT       = 1,
    BV_CHECK      = 2,
    BV_BODY_MUL   = 3,
    BV_BODY_ADD   = 4,
    BV_BODY_DEC   = 5,
    BV_HALT       = 6,
};

__declspec(noinline)
int vm_byte_loop_target(int x) {
    unsigned char state = 0;
    int n = 0;
    int pc = BV_LOAD;

    while (1) {
        if (pc == BV_LOAD) {
            state = (unsigned char)x;
            n = (x >> 8) & 0xF;
            pc = BV_INIT;
        } else if (pc == BV_INIT) {
            pc = BV_CHECK;
        } else if (pc == BV_CHECK) {
            pc = (n > 0) ? BV_BODY_MUL : BV_HALT;
        } else if (pc == BV_BODY_MUL) {
            state = (unsigned char)(state * 13);
            pc = BV_BODY_ADD;
        } else if (pc == BV_BODY_ADD) {
            state = (unsigned char)(state + 5);
            pc = BV_BODY_DEC;
        } else if (pc == BV_BODY_DEC) {
            n = n - 1;
            pc = BV_CHECK;
        } else if (pc == BV_HALT) {
            return (int)state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_byte_loop(0xCAFE)=%d vm_byte_loop(0xFFFF)=%d\n",
           vm_byte_loop_target(0xCAFE),
           vm_byte_loop_target(0xFFFF));
    return 0;
}
