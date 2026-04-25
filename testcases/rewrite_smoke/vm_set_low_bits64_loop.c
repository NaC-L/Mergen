/* PC-state VM: r |= r - 1 per iter (set all bits below lowest set bit):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r | (r - 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_set_low_bits64_loop_target.
 *
 * Distinct from:
 *   - vm_clear_low_bit64_loop (`r & (r-1)` - clear, not set)
 *   - vm_bit_smear_down64_loop (`r | (r >> 1)` - shift-based)
 *
 * Tests `r | (r - 1)` self-arith OR idiom.  After 1 iter, all bits
 * below the lowest 1 in r become set; result stable from iter 2.
 * For x=0: r=0, r-1 underflows to all-1s, OR gives all-1s.
 */
#include <stdio.h>
#include <stdint.h>

enum SbVmPc {
    SB_INIT_ALL = 0,
    SB_CHECK    = 1,
    SB_BODY     = 2,
    SB_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_set_low_bits64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = SB_INIT_ALL;

    while (1) {
        if (pc == SB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = SB_CHECK;
        } else if (pc == SB_CHECK) {
            pc = (n > 0ull) ? SB_BODY : SB_HALT;
        } else if (pc == SB_BODY) {
            r = r | (r - 1ull);
            n = n - 1ull;
            pc = SB_CHECK;
        } else if (pc == SB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_set_low_bits64(0x100)=%llu\n",
           (unsigned long long)vm_set_low_bits64_loop_target(0x100ull));
    return 0;
}
