/* PC-state VM that counts trailing zero bits in x (capped at 32).
 * Lift target: vm_ctz_loop_target.
 * Goal: cover a counted loop with EARLY BREAK on LSB-set predicate.  Loop
 * counter doubles as both trip count and result.  Distinct from
 * vm_kernighan_loop (which counts set bits, not trailing-zero position) and
 * vm_palindrome_loop (which has two distinct halt PCs).
 */
#include <stdio.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_CHECK_LIM  = 2,
    CZ_TEST_LSB   = 3,
    CZ_BODY_SHR   = 4,
    CZ_BODY_INC   = 5,
    CZ_HALT       = 6,
};

__declspec(noinline)
int vm_ctz_loop_target(int x) {
    int v     = 0;
    int count = 0;
    int pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            v = x;
            count = 0;
            pc = CZ_INIT;
        } else if (pc == CZ_INIT) {
            pc = CZ_CHECK_LIM;
        } else if (pc == CZ_CHECK_LIM) {
            pc = (count < 32) ? CZ_TEST_LSB : CZ_HALT;
        } else if (pc == CZ_TEST_LSB) {
            pc = ((v & 1) != 0) ? CZ_HALT : CZ_BODY_SHR;
        } else if (pc == CZ_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = CZ_BODY_INC;
        } else if (pc == CZ_BODY_INC) {
            count = count + 1;
            pc = CZ_CHECK_LIM;
        } else if (pc == CZ_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_ctz_loop(0xC000)=%d vm_ctz_loop(0x10000)=%d\n",
           vm_ctz_loop_target(0xC000), vm_ctz_loop_target(0x10000));
    return 0;
}
