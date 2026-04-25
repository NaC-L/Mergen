/* PC-state VM that allocates THREE stack arrays of different element
 * widths in the same frame and sums across them.
 * Lift target: vm_mixed_width_array_loop_target.
 * Goal: stress heterogeneous stack-frame layout (int[4] + short[4] +
 * signed char[4]).  All three are filled in one fill loop and then
 * accumulated in a separate sum loop, exercising sext i16 + sext i8 +
 * native i32 loads from the same stack region.
 */
#include <stdio.h>

enum MwVmPc {
    MW_LOAD       = 0,
    MW_INIT_FILL  = 1,
    MW_FILL_CHECK = 2,
    MW_FILL_BODY  = 3,
    MW_FILL_INC   = 4,
    MW_INIT_SUM   = 5,
    MW_SUM_CHECK  = 6,
    MW_SUM_BODY   = 7,
    MW_SUM_INC    = 8,
    MW_HALT       = 9,
};

__declspec(noinline)
int vm_mixed_width_array_loop_target(int x) {
    int          a[4];
    short        b[4];
    signed char  c[4];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = MW_LOAD;

    while (1) {
        if (pc == MW_LOAD) {
            seed = x;
            pc = MW_INIT_FILL;
        } else if (pc == MW_INIT_FILL) {
            idx = 0;
            pc = MW_FILL_CHECK;
        } else if (pc == MW_FILL_CHECK) {
            pc = (idx < 4) ? MW_FILL_BODY : MW_INIT_SUM;
        } else if (pc == MW_FILL_BODY) {
            a[idx] = seed * (idx + 1);
            b[idx] = (short)(seed + idx * 7);
            c[idx] = (signed char)(seed - idx * 5);
            pc = MW_FILL_INC;
        } else if (pc == MW_FILL_INC) {
            idx = idx + 1;
            pc = MW_FILL_CHECK;
        } else if (pc == MW_INIT_SUM) {
            idx = 0;
            pc = MW_SUM_CHECK;
        } else if (pc == MW_SUM_CHECK) {
            pc = (idx < 4) ? MW_SUM_BODY : MW_HALT;
        } else if (pc == MW_SUM_BODY) {
            sum = sum + a[idx] + (int)b[idx] + (int)c[idx];
            pc = MW_SUM_INC;
        } else if (pc == MW_SUM_INC) {
            idx = idx + 1;
            pc = MW_SUM_CHECK;
        } else if (pc == MW_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_mixed_width(10000)=%d vm_mixed_width(40000)=%d\n",
           vm_mixed_width_array_loop_target(10000),
           vm_mixed_width_array_loop_target(40000));
    return 0;
}
