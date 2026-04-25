/* PC-state VM that counts u16 words with high bit set (w >= 0x8000):
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w >= 0x8000) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_uge_thresh_count64_loop_target.
 *
 * Tests `icmp uge` predicate at u16 stride.  Word-stride counterpart
 * to vm_byte_uge_thresh_count64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WgVmPc {
    WG_INIT_ALL = 0,
    WG_CHECK    = 1,
    WG_BODY     = 2,
    WG_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_uge_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WG_INIT_ALL;

    while (1) {
        if (pc == WG_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WG_CHECK;
        } else if (pc == WG_CHECK) {
            pc = (n > 0ull) ? WG_BODY : WG_HALT;
        } else if (pc == WG_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w >= 0x8000ull) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WG_CHECK;
        } else if (pc == WG_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_uge_thresh_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_uge_thresh_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
