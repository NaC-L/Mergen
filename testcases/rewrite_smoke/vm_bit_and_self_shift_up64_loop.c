/* PC-state VM: r &= r << 1 per iter (shrinks runs from the bottom):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r & (r << 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_and_self_shift_up64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_and_self_shift_down64_loop (lshr-1 direction)
 *   - vm_bit_smear_up64_loop            (OR fold instead of AND)
 *
 * Tests `r &= r << 1` self-shift AND chain.  Each iter shrinks runs
 * of consecutive 1s from the LOW end (mirror of lshr direction which
 * shrinks from the high end).
 */
#include <stdio.h>
#include <stdint.h>

enum BvVmPc {
    BV_INIT_ALL = 0,
    BV_CHECK    = 1,
    BV_BODY     = 2,
    BV_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_bit_and_self_shift_up64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BV_INIT_ALL;

    while (1) {
        if (pc == BV_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BV_CHECK;
        } else if (pc == BV_CHECK) {
            pc = (n > 0ull) ? BV_BODY : BV_HALT;
        } else if (pc == BV_BODY) {
            r = r & (r << 1);
            n = n - 1ull;
            pc = BV_CHECK;
        } else if (pc == BV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bit_and_self_shift_up64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bit_and_self_shift_up64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
