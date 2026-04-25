/* PC-state VM that smears bits downward via r |= r>>1 over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r | (r >> 1);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bit_smear_down64_loop_target.
 *
 * Distinct from:
 *   - vm_dynlshr_accum_byte64_loop (lshr accumulator with byte XOR)
 *   - vm_xor_shifted_self_byte64_loop (XOR with self-shift, has byte stream)
 *   - vm_byte_andfold64_loop (AND fold over bytes)
 *
 * Tests `r |= r >> 1` self-shift OR chain - smears the highest set
 * bit of r downward by n positions per iter.  After enough iters
 * (>= log2(input)) the result becomes a contiguous 1-mask from the
 * top bit down to bit 0.  Pure single-state self-shift OR.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_bit_smear_down64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (n > 0ull) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            r = r | (r >> 1);
            n = n - 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bit_smear_down64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_bit_smear_down64_loop_target(0x8000000000000000ull));
    return 0;
}
