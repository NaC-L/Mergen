/* PC-state VM: per-iter test bit at position i of byte i:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     cnt += (b >> i) & 1;
 *     s >>= 8;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_bit_pos_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (icmp eq counter)
 *   - vm_byte_lt_thresh_count64_loop (icmp ult counter)
 *   - vm_bitfetch_window64_loop (dynamic LSHR but OR-pack not count)
 *
 * Tests `((b >> i) & 1)` add chain - dynamic LSHR amount per iter
 * combined with `& 1` zext-style mask, summed.  All-FF: each byte's
 * bit at position i is always set -> cnt=n.
 */
#include <stdio.h>
#include <stdint.h>

enum BpVmPc {
    BP_INIT_ALL = 0,
    BP_CHECK    = 1,
    BP_BODY     = 2,
    BP_INC      = 3,
    BP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byte_bit_pos_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    uint64_t i   = 0;
    int      pc  = BP_INIT_ALL;

    while (1) {
        if (pc == BP_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            i = 0ull;
            pc = BP_CHECK;
        } else if (pc == BP_CHECK) {
            pc = (i < n) ? BP_BODY : BP_HALT;
        } else if (pc == BP_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b >> i) & 1ull);
            s = s >> 8;
            pc = BP_INC;
        } else if (pc == BP_INC) {
            i = i + 1ull;
            pc = BP_CHECK;
        } else if (pc == BP_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_bit_pos_count64(0x8040201008040201)=%llu\n",
           (unsigned long long)vm_byte_bit_pos_count64_loop_target(0x8040201008040201ull));
    return 0;
}
