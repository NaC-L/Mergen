/* PC-state VM that counts u16 words with w <= 0x7FFF (low half):
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w <= 0x7FFF) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_ule_thresh_count64_loop_target.
 *
 * Tests `icmp ule` predicate at u16 stride.  Word-stride counterpart
 * to vm_byte_ule_thresh_count64_loop.  Completes the ule cmp-counter
 * matrix at byte and word strides.
 */
#include <stdio.h>
#include <stdint.h>

enum WleVmPc {
    WLE_INIT_ALL = 0,
    WLE_CHECK    = 1,
    WLE_BODY     = 2,
    WLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_ule_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WLE_INIT_ALL;

    while (1) {
        if (pc == WLE_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WLE_CHECK;
        } else if (pc == WLE_CHECK) {
            pc = (n > 0ull) ? WLE_BODY : WLE_HALT;
        } else if (pc == WLE_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w <= 0x7FFFull) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WLE_CHECK;
        } else if (pc == WLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_ule_thresh_count64(0x7FFF7FFF7FFF7FFF)=%llu\n",
           (unsigned long long)vm_word_ule_thresh_count64_loop_target(0x7FFF7FFF7FFF7FFFull));
    return 0;
}
