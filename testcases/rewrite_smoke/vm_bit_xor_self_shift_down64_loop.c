/* PC-state VM: r ^= r >> 1 per iteration (Gray-code-like transform):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r ^ (r >> 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_xor_self_shift_down64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_smear_down64_loop (`r |= r >> 1` - OR fold instead of XOR)
 *   - vm_dynlshr_accum_byte64_loop (lshr with byte XOR)
 *   - vm_xor_shifted_self_byte64_loop (XOR with shifted self + byte)
 *
 * Tests `r ^= r >> 1` self-shift XOR chain.  Single-state pure
 * self-XOR with lshr-by-1.  After 1 iter, r becomes the Gray code
 * encoding of x; further iters produce additional cumulative XORs.
 */
#include <stdio.h>
#include <stdint.h>

enum BxVmPc {
    BX_INIT_ALL = 0,
    BX_CHECK    = 1,
    BX_BODY     = 2,
    BX_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_bit_xor_self_shift_down64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BX_INIT_ALL;

    while (1) {
        if (pc == BX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BX_CHECK;
        } else if (pc == BX_CHECK) {
            pc = (n > 0ull) ? BX_BODY : BX_HALT;
        } else if (pc == BX_BODY) {
            r = r ^ (r >> 1);
            n = n - 1ull;
            pc = BX_CHECK;
        } else if (pc == BX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bit_xor_self_shift_down64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_bit_xor_self_shift_down64_loop_target(0x8000000000000000ull));
    return 0;
}
