/* PC-state VM: per-iter test bit at position i of word i:
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt += (w >> i) & 1;
 *     s >>= 16;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_bit_pos_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_bit_pos_count64_loop (8-bit stride, i ranges 0..7)
 *   - vm_word_eq_first_count64_loop (eq cmp counter)
 *
 * Tests `((w >> i) & 1)` add chain at u16 stride - dynamic LSHR amount
 * per iter combined with `& 1` mask, summed.  i ranges 0..3.
 */
#include <stdio.h>
#include <stdint.h>

enum WbpVmPc {
    WBP_INIT_ALL = 0,
    WBP_CHECK    = 1,
    WBP_BODY     = 2,
    WBP_INC      = 3,
    WBP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_bit_pos_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    uint64_t i   = 0;
    int      pc  = WBP_INIT_ALL;

    while (1) {
        if (pc == WBP_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            i = 0ull;
            pc = WBP_CHECK;
        } else if (pc == WBP_CHECK) {
            pc = (i < n) ? WBP_BODY : WBP_HALT;
        } else if (pc == WBP_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w >> i) & 1ull);
            s = s >> 16;
            pc = WBP_INC;
        } else if (pc == WBP_INC) {
            i = i + 1ull;
            pc = WBP_CHECK;
        } else if (pc == WBP_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_bit_pos_count64(0x0008000400020001)=%llu\n",
           (unsigned long long)vm_word_bit_pos_count64_loop_target(0x0008000400020001ull));
    return 0;
}
