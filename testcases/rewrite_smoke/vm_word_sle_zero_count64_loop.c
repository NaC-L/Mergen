/* PC-state VM that counts signed u16 words <= 0:
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     cnt = cnt + ((sw <= 0) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_sle_zero_count64_loop_target.
 *
 * Tests `icmp sle 0` at u16 stride.  Word-stride counterpart of
 * vm_byte_sle_zero_count64_loop.  Completes the signed-predicate
 * cmp-counter matrix at u16 stride (slt/sle/sgt/sge).
 */
#include <stdio.h>
#include <stdint.h>

enum WsleVmPc {
    WSLE_INIT_ALL = 0,
    WSLE_CHECK    = 1,
    WSLE_BODY     = 2,
    WSLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_sle_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WSLE_INIT_ALL;

    while (1) {
        if (pc == WSLE_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WSLE_CHECK;
        } else if (pc == WSLE_CHECK) {
            pc = (n > 0ull) ? WSLE_BODY : WSLE_HALT;
        } else if (pc == WSLE_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            cnt = cnt + ((sw <= (int16_t)0) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WSLE_CHECK;
        } else if (pc == WSLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_sle_zero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_sle_zero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
