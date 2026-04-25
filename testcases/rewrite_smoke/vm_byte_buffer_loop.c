/* PC-state VM that fills a 16-byte stack buffer (uint8_t buf[16]) and
 * sums it in a separate pass.
 * Lift target: vm_byte_buffer_loop_target.
 * Goal: cover an i8-element stack array (distinct from int[] arrays and
 * from the scalar-i8 vm_byte_loop case).  Two PC-state passes (fill +
 * accumulate); both have a fixed 16-trip bound and may be unrolled.
 */
#include <stdio.h>

enum BbVmPc {
    BB_LOAD       = 0,
    BB_INIT_FILL  = 1,
    BB_FILL_CHECK = 2,
    BB_FILL_BODY  = 3,
    BB_FILL_INC   = 4,
    BB_INIT_SUM   = 5,
    BB_SUM_CHECK  = 6,
    BB_SUM_BODY   = 7,
    BB_SUM_INC    = 8,
    BB_HALT       = 9,
};

__declspec(noinline)
int vm_byte_buffer_loop_target(int x) {
    unsigned char buf[16];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = BB_LOAD;

    while (1) {
        if (pc == BB_LOAD) {
            seed = x & 0xFF;
            pc = BB_INIT_FILL;
        } else if (pc == BB_INIT_FILL) {
            idx = 0;
            pc = BB_FILL_CHECK;
        } else if (pc == BB_FILL_CHECK) {
            pc = (idx < 16) ? BB_FILL_BODY : BB_INIT_SUM;
        } else if (pc == BB_FILL_BODY) {
            buf[idx] = (unsigned char)((idx * 7 + seed) & 0xFF);
            pc = BB_FILL_INC;
        } else if (pc == BB_FILL_INC) {
            idx = idx + 1;
            pc = BB_FILL_CHECK;
        } else if (pc == BB_INIT_SUM) {
            idx = 0;
            pc = BB_SUM_CHECK;
        } else if (pc == BB_SUM_CHECK) {
            pc = (idx < 16) ? BB_SUM_BODY : BB_HALT;
        } else if (pc == BB_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = BB_SUM_INC;
        } else if (pc == BB_SUM_INC) {
            idx = idx + 1;
            pc = BB_SUM_CHECK;
        } else if (pc == BB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_byte_buffer_loop(0x55)=%d vm_byte_buffer_loop(0xFF)=%d\n",
           vm_byte_buffer_loop_target(0x55),
           vm_byte_buffer_loop_target(0xFF));
    return 0;
}
