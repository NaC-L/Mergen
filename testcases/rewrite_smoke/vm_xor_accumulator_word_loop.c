/* PC-state VM accumulating XOR of i*k for i in 0..3, where k = x & 0xFFFF.
 * Lift target: vm_xor_accumulator_word_loop_target.
 *
 * Distinct from:
 *   - vm_xor_accumulator_loop (8-trip, byte key)
 *
 * Fixed 4-trip loop body uses multiplication and XOR (not add) into
 * the accumulator with a u16 word-derived symbolic key, so the lifter
 * cannot collapse the XOR accumulator to a constant.
 */
#include <stdio.h>

enum XawVmPc {
    XAW_INIT      = 0,
    XAW_LOAD_KEY  = 1,
    XAW_INIT_ACC  = 2,
    XAW_INIT_IDX  = 3,
    XAW_CHECK     = 4,
    XAW_BODY_MUL  = 5,
    XAW_BODY_XOR  = 6,
    XAW_BODY_INC  = 7,
    XAW_HALT      = 8,
};

__declspec(noinline)
int vm_xor_accumulator_word_loop_target(int x) {
    int key  = 0;
    int acc  = 0;
    int idx  = 0;
    int prod = 0;
    int pc   = XAW_INIT;

    while (1) {
        if (pc == XAW_INIT) {
            pc = XAW_LOAD_KEY;
        } else if (pc == XAW_LOAD_KEY) {
            key = x & 0xFFFF;
            pc = XAW_INIT_ACC;
        } else if (pc == XAW_INIT_ACC) {
            acc = 0;
            pc = XAW_INIT_IDX;
        } else if (pc == XAW_INIT_IDX) {
            idx = 0;
            pc = XAW_CHECK;
        } else if (pc == XAW_CHECK) {
            pc = (idx < 4) ? XAW_BODY_MUL : XAW_HALT;
        } else if (pc == XAW_BODY_MUL) {
            prod = idx * key;
            pc = XAW_BODY_XOR;
        } else if (pc == XAW_BODY_XOR) {
            acc = acc ^ prod;
            pc = XAW_BODY_INC;
        } else if (pc == XAW_BODY_INC) {
            idx = idx + 1;
            pc = XAW_CHECK;
        } else if (pc == XAW_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_xor_accumulator_word_loop(0xCAFE)=%d\n",
           vm_xor_accumulator_word_loop_target(0xCAFE));
    return 0;
}
