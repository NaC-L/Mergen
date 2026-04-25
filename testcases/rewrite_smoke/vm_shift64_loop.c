/* PC-state VM with a true 64-bit recurrence: state = state * GOLDEN64 + ...
 * extracts the high byte each iteration into a 32-bit sum.
 * Lift target: vm_shift64_loop_target.
 * Goal: cover loop body that requires REAL 64-bit arithmetic - the
 * multiplier 0x9E3779B97F4A7C15 doesn't fit in 32 bits so the lifter has
 * to retain mul i64 + lshr i64 + trunc rather than narrowing to i32.
 */
#include <stdio.h>

enum S6VmPc {
    S6_LOAD       = 0,
    S6_INIT       = 1,
    S6_CHECK      = 2,
    S6_BODY_MUL   = 3,
    S6_BODY_ADD   = 4,
    S6_BODY_HI    = 5,
    S6_BODY_FOLD  = 6,
    S6_BODY_INC   = 7,
    S6_HALT       = 8,
};

__declspec(noinline)
int vm_shift64_loop_target(int x) {
    unsigned long long state = 0;
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int hi    = 0;
    int pc    = S6_LOAD;

    while (1) {
        if (pc == S6_LOAD) {
            limit = (x & 7) + 1;
            state = (unsigned long long)(unsigned)x
                  | ((unsigned long long)(unsigned)x << 32);
            sum = 0;
            pc = S6_INIT;
        } else if (pc == S6_INIT) {
            idx = 0;
            pc = S6_CHECK;
        } else if (pc == S6_CHECK) {
            pc = (idx < limit) ? S6_BODY_MUL : S6_HALT;
        } else if (pc == S6_BODY_MUL) {
            state = state * 0x9E3779B97F4A7C15ULL;
            pc = S6_BODY_ADD;
        } else if (pc == S6_BODY_ADD) {
            state = state + (unsigned long long)(idx * 13);
            pc = S6_BODY_HI;
        } else if (pc == S6_BODY_HI) {
            hi = (int)((state >> 56) & 0xFF);
            pc = S6_BODY_FOLD;
        } else if (pc == S6_BODY_FOLD) {
            sum = sum + hi;
            pc = S6_BODY_INC;
        } else if (pc == S6_BODY_INC) {
            idx = idx + 1;
            pc = S6_CHECK;
        } else if (pc == S6_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_shift64_loop(0xCAFE)=%d vm_shift64_loop(0xDEADBEEF)=%d\n",
           vm_shift64_loop_target(0xCAFE),
           vm_shift64_loop_target((int)0xDEADBEEFu));
    return 0;
}
