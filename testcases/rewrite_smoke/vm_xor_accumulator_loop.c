/* PC-state VM accumulating XOR of i*k for i in 0..7, where k = x & 0xFF.
 * Lift target: vm_xor_accumulator_loop_target.
 * Goal: cover a fixed-trip-count loop whose body uses multiplication and
 * XOR (not add) into the accumulator.  The constant key is replaced by a
 * symbolic key derived from x, so the lifter cannot collapse the XOR
 * accumulator to a constant.
 */
#include <stdio.h>

enum XorVmPc {
    XV_INIT      = 0,
    XV_LOAD_KEY  = 1,
    XV_INIT_ACC  = 2,
    XV_INIT_IDX  = 3,
    XV_CHECK     = 4,
    XV_BODY_MUL  = 5,
    XV_BODY_XOR  = 6,
    XV_BODY_INC  = 7,
    XV_HALT      = 8,
};

__declspec(noinline)
int vm_xor_accumulator_loop_target(int x) {
    int key  = 0;
    int acc  = 0;
    int idx  = 0;
    int prod = 0;
    int pc   = XV_INIT;

    while (1) {
        if (pc == XV_INIT) {
            pc = XV_LOAD_KEY;
        } else if (pc == XV_LOAD_KEY) {
            key = x & 0xFF;
            pc = XV_INIT_ACC;
        } else if (pc == XV_INIT_ACC) {
            acc = 0;
            pc = XV_INIT_IDX;
        } else if (pc == XV_INIT_IDX) {
            idx = 0;
            pc = XV_CHECK;
        } else if (pc == XV_CHECK) {
            pc = (idx < 8) ? XV_BODY_MUL : XV_HALT;
        } else if (pc == XV_BODY_MUL) {
            prod = idx * key;
            pc = XV_BODY_XOR;
        } else if (pc == XV_BODY_XOR) {
            acc = acc ^ prod;
            pc = XV_BODY_INC;
        } else if (pc == XV_BODY_INC) {
            idx = idx + 1;
            pc = XV_CHECK;
        } else if (pc == XV_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_xor_accumulator_loop(15)=%d vm_xor_accumulator_loop(255)=%d\n",
           vm_xor_accumulator_loop_target(15), vm_xor_accumulator_loop_target(255));
    return 0;
}
