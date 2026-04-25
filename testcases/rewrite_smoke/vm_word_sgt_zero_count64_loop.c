/* PC-state VM that counts signed u16 words > 0:
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     cnt = cnt + ((sw > 0) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_sgt_zero_count64_loop_target.
 *
 * Tests `icmp sgt 0` at u16 stride.  Word-stride counterpart of
 * vm_byte_sgt_zero_count64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WsgVmPc {
    WSG_INIT_ALL = 0,
    WSG_CHECK    = 1,
    WSG_BODY     = 2,
    WSG_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_sgt_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WSG_INIT_ALL;

    while (1) {
        if (pc == WSG_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WSG_CHECK;
        } else if (pc == WSG_CHECK) {
            pc = (n > 0ull) ? WSG_BODY : WSG_HALT;
        } else if (pc == WSG_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            cnt = cnt + ((sw > (int16_t)0) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WSG_CHECK;
        } else if (pc == WSG_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_sgt_zero_count64(0x7FFF7FFF7FFF7FFF)=%llu\n",
           (unsigned long long)vm_word_sgt_zero_count64_loop_target(0x7FFF7FFF7FFF7FFFull));
    return 0;
}
