/* PC-state VM applying a piecewise linear function repeatedly to a single
 * accumulator.
 * Lift target: vm_piecewise_loop_target.
 * Goal: cover a loop body that selects one of three transformations based
 * on which range the current value falls in, with a single sequential
 * dependency on the previous iteration's result.  Distinct from
 * vm_classify_loop (which counts class membership) and vm_collatz_loop
 * (data-dependent path with two branches).
 */
#include <stdio.h>

enum PwVmPc {
    PW_LOAD       = 0,
    PW_INIT       = 1,
    PW_CHECK      = 2,
    PW_BODY_TEST_LO = 3,
    PW_BODY_TEST_HI = 4,
    PW_BODY_DOUBLE = 5,
    PW_BODY_OFFSET = 6,
    PW_BODY_SHRINK = 7,
    PW_BODY_DEC   = 8,
    PW_HALT       = 9,
};

__declspec(noinline)
int vm_piecewise_loop_target(int x) {
    int v   = 0;
    int n   = 0;
    int pc  = PW_LOAD;

    while (1) {
        if (pc == PW_LOAD) {
            v = x & 0xFF;
            n = (x >> 8) & 0xF;
            pc = PW_INIT;
        } else if (pc == PW_INIT) {
            pc = PW_CHECK;
        } else if (pc == PW_CHECK) {
            pc = (n > 0) ? PW_BODY_TEST_LO : PW_HALT;
        } else if (pc == PW_BODY_TEST_LO) {
            pc = (v < 50) ? PW_BODY_DOUBLE : PW_BODY_TEST_HI;
        } else if (pc == PW_BODY_TEST_HI) {
            pc = (v < 200) ? PW_BODY_OFFSET : PW_BODY_SHRINK;
        } else if (pc == PW_BODY_DOUBLE) {
            v = (v * 2) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_OFFSET) {
            v = (v + 30) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_SHRINK) {
            v = (v - 100) & 0xFFFF;
            pc = PW_BODY_DEC;
        } else if (pc == PW_BODY_DEC) {
            n = n - 1;
            pc = PW_CHECK;
        } else if (pc == PW_HALT) {
            return v;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_piecewise_loop(0x709)=%d vm_piecewise_loop(0xFFF)=%d\n",
           vm_piecewise_loop_target(0x709), vm_piecewise_loop_target(0xFFF));
    return 0;
}
