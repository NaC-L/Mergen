/* PC-state VM that fills a signed-char[16] stack array and accumulates
 * via sign-extending byte loads.
 * Lift target: vm_sbyte_array_loop_target.
 * Goal: cover an i8-element stack array with SIGNED element type
 * (sext i8 -> i32 at use sites), distinct from vm_byte_buffer_loop which
 * uses unsigned-char[] (zext i8).  Mirrors the i16 sext/zext pair.
 */
#include <stdio.h>

enum SbVmPc {
    SB_LOAD       = 0,
    SB_INIT_FILL  = 1,
    SB_FILL_CHECK = 2,
    SB_FILL_BODY  = 3,
    SB_FILL_INC   = 4,
    SB_INIT_SUM   = 5,
    SB_SUM_CHECK  = 6,
    SB_SUM_BODY   = 7,
    SB_SUM_INC    = 8,
    SB_HALT       = 9,
};

__declspec(noinline)
int vm_sbyte_array_loop_target(int x) {
    signed char buf[16];
    int idx  = 0;
    int sum  = 0;
    signed char seed = 0;
    int pc   = SB_LOAD;

    while (1) {
        if (pc == SB_LOAD) {
            seed = (signed char)(x & 0xFF);
            pc = SB_INIT_FILL;
        } else if (pc == SB_INIT_FILL) {
            idx = 0;
            pc = SB_FILL_CHECK;
        } else if (pc == SB_FILL_CHECK) {
            pc = (idx < 16) ? SB_FILL_BODY : SB_INIT_SUM;
        } else if (pc == SB_FILL_BODY) {
            buf[idx] = (signed char)((int)seed * (idx - 4));
            pc = SB_FILL_INC;
        } else if (pc == SB_FILL_INC) {
            idx = idx + 1;
            pc = SB_FILL_CHECK;
        } else if (pc == SB_INIT_SUM) {
            idx = 0;
            pc = SB_SUM_CHECK;
        } else if (pc == SB_SUM_CHECK) {
            pc = (idx < 16) ? SB_SUM_BODY : SB_HALT;
        } else if (pc == SB_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = SB_SUM_INC;
        } else if (pc == SB_SUM_INC) {
            idx = idx + 1;
            pc = SB_SUM_CHECK;
        } else if (pc == SB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_sbyte_array_loop(10)=%d vm_sbyte_array_loop(0xFF)=%d\n",
           vm_sbyte_array_loop_target(10),
           vm_sbyte_array_loop_target(0xFF));
    return 0;
}
