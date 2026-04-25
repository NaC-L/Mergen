/* PC-state VM that counts signed u16 words >= 0 (non-negative):
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     cnt = cnt + ((sw >= 0) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_sge_zero_count64_loop_target.
 *
 * Tests `icmp sge 0` at u16 stride.  Word-stride counterpart of
 * vm_byte_sge_zero_count64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WsgeVmPc {
    WSGE_INIT_ALL = 0,
    WSGE_CHECK    = 1,
    WSGE_BODY     = 2,
    WSGE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_sge_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WSGE_INIT_ALL;

    while (1) {
        if (pc == WSGE_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WSGE_CHECK;
        } else if (pc == WSGE_CHECK) {
            pc = (n > 0ull) ? WSGE_BODY : WSGE_HALT;
        } else if (pc == WSGE_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            cnt = cnt + ((sw >= (int16_t)0) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WSGE_CHECK;
        } else if (pc == WSGE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_sge_zero_count64(0x7FFF7FFF7FFF7FFF)=%llu\n",
           (unsigned long long)vm_word_sge_zero_count64_loop_target(0x7FFF7FFF7FFF7FFFull));
    return 0;
}
