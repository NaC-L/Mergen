/* PC-state VM: r &= r >> 1 per iter (shrinks runs of consecutive 1s):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r & (r >> 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_and_self_shift_down64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_smear_down64_loop          (`|=` instead of `&=`)
 *   - vm_bit_xor_self_shift_down64_loop (`^=` instead of `&=`)
 *
 * Tests `r &= r >> 1` self-shift AND chain.  After 1 iter, each
 * run of k consecutive 1s shrinks to k-1.  After n iters, only
 * runs of length > n survive.  All-1s n=8: shrinks to 64-8=56-bit
 * leading-1 mask = 0x00FFFFFFFFFFFFFF = 72057594037927935.
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
uint64_t vm_bit_and_self_shift_down64_loop_target(uint64_t x) {
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
            r = r & (r >> 1);
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
    printf("vm_bit_and_self_shift_down64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bit_and_self_shift_down64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
