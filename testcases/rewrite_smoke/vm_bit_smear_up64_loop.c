/* PC-state VM that smears bits upward via r |= r<<1 over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r | (r << 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_smear_up64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_smear_down64_loop (smears via r >> 1 OR back)
 *
 * Tests `r |= r << 1` self-shift OR chain - smears any set bit
 * upward by n positions per iter.  After n iters, an isolated
 * bit at position k becomes a contiguous 1-mask from bit k to
 * bit k+n.  Pure single-state self-shift OR.
 */
#include <stdio.h>
#include <stdint.h>

enum BuVmPc {
    BU_INIT_ALL = 0,
    BU_CHECK    = 1,
    BU_BODY     = 2,
    BU_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_bit_smear_up64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BU_INIT_ALL;

    while (1) {
        if (pc == BU_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BU_CHECK;
        } else if (pc == BU_CHECK) {
            pc = (n > 0ull) ? BU_BODY : BU_HALT;
        } else if (pc == BU_BODY) {
            r = r | (r << 1);
            n = n - 1ull;
            pc = BU_CHECK;
        } else if (pc == BU_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bit_smear_up64(0x1)=%llu\n",
           (unsigned long long)vm_bit_smear_up64_loop_target(0x1ull));
    return 0;
}
