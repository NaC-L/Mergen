/* PC-state VM that counts u16 words equal to the first word:
 *
 *   n = (x & 3) + 1;
 *   s = x; first = s & 0xFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w == first) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_eq_first_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (8-bit stride)
 *   - vm_word_lt_thresh_count64_loop (ult vs CONSTANT, not eq vs reference)
 *
 * Tests `icmp eq` cmp-counter at u16 stride, where the comparand is
 * a captured reference (first), not a constant.  4 stateful slots
 * (n, s, first, cnt) within the documented budget.
 */
#include <stdio.h>
#include <stdint.h>

enum WeVmPc {
    WE_INIT_ALL = 0,
    WE_CHECK    = 1,
    WE_BODY     = 2,
    WE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_eq_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = WE_INIT_ALL;

    while (1) {
        if (pc == WE_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            first = x & 0xFFFFull;
            cnt = 0ull;
            pc = WE_CHECK;
        } else if (pc == WE_CHECK) {
            pc = (n > 0ull) ? WE_BODY : WE_HALT;
        } else if (pc == WE_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w == first) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WE_CHECK;
        } else if (pc == WE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_eq_first_count64(0x3000300030003)=%llu\n",
           (unsigned long long)vm_word_eq_first_count64_loop_target(0x0003000300030003ull));
    return 0;
}
