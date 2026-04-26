/* PC-state VM that counts u16 words not equal to the first word:
 *
 *   n = (x & 3) + 1;
 *   s = x; first = s & 0xFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w != first) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_ne_first_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_ne_first_count64_loop (8-bit stride)
 *   - vm_word_eq_first_count64_loop (eq complement at the same stride)
 *
 * Tests `icmp ne` cmp-counter with captured-reference comparand at u16
 * stride.  4 stateful slots (n, s, first, cnt) within budget.
 */
#include <stdio.h>
#include <stdint.h>

enum WneVmPc {
    WNE_INIT_ALL = 0,
    WNE_CHECK    = 1,
    WNE_BODY     = 2,
    WNE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_ne_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = WNE_INIT_ALL;

    while (1) {
        if (pc == WNE_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            first = x & 0xFFFFull;
            cnt = 0ull;
            pc = WNE_CHECK;
        } else if (pc == WNE_CHECK) {
            pc = (n > 0ull) ? WNE_BODY : WNE_HALT;
        } else if (pc == WNE_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w != first) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WNE_CHECK;
        } else if (pc == WNE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_ne_first_count64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_word_ne_first_count64_loop_target(0xDEADBEEFull));
    return 0;
}
