/* PC-state VM whose body chains TWO distinct intrinsic calls per iteration:
 *   sum += __builtin_popcount(v) + __builtin_bswap32(v)
 * Lift target: vm_mixed_intrinsics_loop_target.
 * Goal: probe whether the documented chain-of-two-calls correctness bug
 * (originally seen in vm_chain_imports_loop with two abs() calls) is
 * specific to abs or generalises to any pair of intrinsics.
 */
#include <stdio.h>

enum MiVmPc {
    MI_LOAD       = 0,
    MI_INIT       = 1,
    MI_CHECK      = 2,
    MI_BODY_VAL   = 3,
    MI_BODY_POPCNT= 4,
    MI_BODY_BSWAP = 5,
    MI_BODY_FOLD  = 6,
    MI_BODY_INC   = 7,
    MI_HALT       = 8,
};

__declspec(noinline)
int vm_mixed_intrinsics_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned pc_r  = 0;
    unsigned bs    = 0;
    int pc         = MI_LOAD;

    while (1) {
        if (pc == MI_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = MI_INIT;
        } else if (pc == MI_INIT) {
            idx = 0;
            pc = MI_CHECK;
        } else if (pc == MI_CHECK) {
            pc = (idx < limit) ? MI_BODY_VAL : MI_HALT;
        } else if (pc == MI_BODY_VAL) {
            v = (unsigned)x ^ (idx * 0x37);
            pc = MI_BODY_POPCNT;
        } else if (pc == MI_BODY_POPCNT) {
            pc_r = (unsigned)__builtin_popcount(v);
            pc = MI_BODY_BSWAP;
        } else if (pc == MI_BODY_BSWAP) {
            bs = __builtin_bswap32(v);
            pc = MI_BODY_FOLD;
        } else if (pc == MI_BODY_FOLD) {
            sum = sum + pc_r + bs;
            pc = MI_BODY_INC;
        } else if (pc == MI_BODY_INC) {
            idx = idx + 1;
            pc = MI_CHECK;
        } else if (pc == MI_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_mixed_intrinsics_loop(0xCAFE)=%u vm_mixed_intrinsics_loop(0xDEADBEEF)=%u\n",
           (unsigned)vm_mixed_intrinsics_loop_target(0xCAFE),
           (unsigned)vm_mixed_intrinsics_loop_target((int)0xDEADBEEFu));
    return 0;
}
