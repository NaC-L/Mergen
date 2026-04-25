/* PC-state VM with i16 (short) arithmetic recurrence.
 * Lift target: vm_short_loop_target.
 * Goal: cover i16 arithmetic inside a VM dispatcher; the result is
 * sign-extended back to int at return.  Distinct from vm_byte_loop (i8)
 * and the i32 / i64 family.
 */
#include <stdio.h>

enum SvVmPc {
    SV_LOAD       = 0,
    SV_INIT       = 1,
    SV_CHECK      = 2,
    SV_BODY_MUL   = 3,
    SV_BODY_ADD   = 4,
    SV_BODY_INC   = 5,
    SV_HALT       = 6,
};

__declspec(noinline)
int vm_short_loop_target(int x) {
    short state = 0;
    int n   = 0;
    int idx = 0;
    int pc  = SV_LOAD;

    while (1) {
        if (pc == SV_LOAD) {
            state = (short)(x & 0xFFFF);
            n = (x >> 16) & 7;
            pc = SV_INIT;
        } else if (pc == SV_INIT) {
            idx = 0;
            pc = SV_CHECK;
        } else if (pc == SV_CHECK) {
            pc = (idx < n) ? SV_BODY_MUL : SV_HALT;
        } else if (pc == SV_BODY_MUL) {
            state = (short)(state * 7);
            pc = SV_BODY_ADD;
        } else if (pc == SV_BODY_ADD) {
            state = (short)(state + idx * 3);
            pc = SV_BODY_INC;
        } else if (pc == SV_BODY_INC) {
            idx = idx + 1;
            pc = SV_CHECK;
        } else if (pc == SV_HALT) {
            return (int)state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_short_loop(0xCAFE)=%d vm_short_loop(0x70000)=%d\n",
           vm_short_loop_target(0xCAFE),
           vm_short_loop_target(0x70000));
    return 0;
}
