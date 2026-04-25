/* PC-state VM that fills a short[8] stack array with signed i16 values
 * and accumulates them via sign-extending loads.
 * Lift target: vm_short_array_loop_target.
 * Goal: cover an i16-element stack array (sext i16 -> i32 at use sites),
 * complementing the i32 / i8 / scalar-i64 / scalar-i16 cases already in
 * the VM corpus.  Symbolic seed keeps mul + sext from being folded.
 */
#include <stdio.h>

enum SaVmPc {
    SA_LOAD       = 0,
    SA_INIT_FILL  = 1,
    SA_FILL_CHECK = 2,
    SA_FILL_BODY  = 3,
    SA_FILL_INC   = 4,
    SA_INIT_SUM   = 5,
    SA_SUM_CHECK  = 6,
    SA_SUM_BODY   = 7,
    SA_SUM_INC    = 8,
    SA_HALT       = 9,
};

__declspec(noinline)
int vm_short_array_loop_target(int x) {
    short buf[8];
    int idx  = 0;
    int sum  = 0;
    short seed = 0;
    int pc   = SA_LOAD;

    while (1) {
        if (pc == SA_LOAD) {
            seed = (short)(x & 0xFFFF);
            pc = SA_INIT_FILL;
        } else if (pc == SA_INIT_FILL) {
            idx = 0;
            pc = SA_FILL_CHECK;
        } else if (pc == SA_FILL_CHECK) {
            pc = (idx < 8) ? SA_FILL_BODY : SA_INIT_SUM;
        } else if (pc == SA_FILL_BODY) {
            buf[idx] = (short)(seed * (short)(idx + 1));
            pc = SA_FILL_INC;
        } else if (pc == SA_FILL_INC) {
            idx = idx + 1;
            pc = SA_FILL_CHECK;
        } else if (pc == SA_INIT_SUM) {
            idx = 0;
            pc = SA_SUM_CHECK;
        } else if (pc == SA_SUM_CHECK) {
            pc = (idx < 8) ? SA_SUM_BODY : SA_HALT;
        } else if (pc == SA_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = SA_SUM_INC;
        } else if (pc == SA_SUM_INC) {
            idx = idx + 1;
            pc = SA_SUM_CHECK;
        } else if (pc == SA_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_short_array_loop(0x1388)=%d vm_short_array_loop(0xCAFE)=%d\n",
           vm_short_array_loop_target(0x1388),
           vm_short_array_loop_target(0xCAFE));
    return 0;
}
