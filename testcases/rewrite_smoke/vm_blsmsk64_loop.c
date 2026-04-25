/* PC-state VM: r ^= r - 1 per iter (BLSMSK idiom):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r ^ (r - 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_blsmsk64_loop_target.
 *
 * Distinct from:
 *   - vm_clear_low_bit64_loop  (`r & (r-1)` - clear lowest)
 *   - vm_set_low_bits64_loop   (`r | (r-1)` - set bits below)
 *   - vm_isolate_low_bit64_loop (`r & -r` - BLSI)
 *
 * Tests `r ^ (r-1)` BLSMSK idiom: produces the mask up to AND
 * including the lowest set bit (e.g. x=8 -> 0xF).  After 1 iter
 * r becomes a low-bit mask; further iters produce different
 * cumulative XOR transforms.
 */
#include <stdio.h>
#include <stdint.h>

enum BkVmPc {
    BK_INIT_ALL = 0,
    BK_CHECK    = 1,
    BK_BODY     = 2,
    BK_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_blsmsk64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BK_INIT_ALL;

    while (1) {
        if (pc == BK_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BK_CHECK;
        } else if (pc == BK_CHECK) {
            pc = (n > 0ull) ? BK_BODY : BK_HALT;
        } else if (pc == BK_BODY) {
            r = r ^ (r - 1ull);
            n = n - 1ull;
            pc = BK_CHECK;
        } else if (pc == BK_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_blsmsk64(0x100)=%llu\n",
           (unsigned long long)vm_blsmsk64_loop_target(0x100ull));
    return 0;
}
