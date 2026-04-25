/* PC-state VM: r ^= r << 1 per iter (XOR with shifted-self upward):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r ^ (r << 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_xor_self_shift_up64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_xor_self_shift_down64_loop (`r ^= r >> 1` - down direction)
 *   - vm_bit_smear_up64_loop            (OR fold instead of XOR)
 *
 * Tests `r ^= r << 1` self-shift XOR chain.  Single-state pure
 * self-XOR with shl-by-1.  Each iter doubles the bit interleave
 * pattern of x in the result.
 */
#include <stdio.h>
#include <stdint.h>

enum BzVmPc {
    BZ_INIT_ALL = 0,
    BZ_CHECK    = 1,
    BZ_BODY     = 2,
    BZ_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_bit_xor_self_shift_up64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BZ_INIT_ALL;

    while (1) {
        if (pc == BZ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BZ_CHECK;
        } else if (pc == BZ_CHECK) {
            pc = (n > 0ull) ? BZ_BODY : BZ_HALT;
        } else if (pc == BZ_BODY) {
            r = r ^ (r << 1);
            n = n - 1ull;
            pc = BZ_CHECK;
        } else if (pc == BZ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bit_xor_self_shift_up64(0x1)=%llu\n",
           (unsigned long long)vm_bit_xor_self_shift_up64_loop_target(0x1ull));
    return 0;
}
