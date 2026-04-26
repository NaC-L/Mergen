/* PC-state VM: per-iter test bit at position i of dword i:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt += (d >> i) & 1;
 *     s >>= 32;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_bit_pos_count64_loop_target.
 *
 * Distinct from:
 *   - vm_word_bit_pos_count64_loop (16-bit stride, i ranges 0..3)
 *   - vm_byte_bit_pos_count64_loop (8-bit stride, i ranges 0..7)
 *
 * Tests `((d >> i) & 1)` add chain at u32 stride - dynamic LSHR amount
 * per iter combined with `& 1` mask, summed.  Trip count is at most 2
 * so i ranges 0..1.
 */
#include <stdio.h>
#include <stdint.h>

enum DbpVmPc {
    DBP_INIT_ALL = 0,
    DBP_CHECK    = 1,
    DBP_BODY     = 2,
    DBP_INC      = 3,
    DBP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dword_bit_pos_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    uint64_t i   = 0;
    int      pc  = DBP_INIT_ALL;

    while (1) {
        if (pc == DBP_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            i = 0ull;
            pc = DBP_CHECK;
        } else if (pc == DBP_CHECK) {
            pc = (i < n) ? DBP_BODY : DBP_HALT;
        } else if (pc == DBP_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d >> i) & 1ull);
            s = s >> 32;
            pc = DBP_INC;
        } else if (pc == DBP_INC) {
            i = i + 1ull;
            pc = DBP_CHECK;
        } else if (pc == DBP_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_bit_pos_count64(0x0000000200000001)=%llu\n",
           (unsigned long long)vm_dword_bit_pos_count64_loop_target(0x0000000200000001ull));
    return 0;
}
