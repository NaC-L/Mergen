/* PC-state VM: count of u16 words strictly > previous word:
 *
 *   n = (x & 3) + 1;
 *   s = x; prev = s & 0xFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w > prev) ? 1 : 0);
 *     prev = w;
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_increase_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_increase_count64_loop (8-bit stride)
 *   - vm_word_eq_first_count64_loop (compares against fixed first)
 *
 * Tests CROSS-ITER u16 word comparison: each iter compares current
 * word to the word from previous iter (stored in `prev` slot).  4
 * stateful slots (n, s, prev, cnt).  First iter always counts 0
 * (w == prev).
 */
#include <stdio.h>
#include <stdint.h>

enum WiVmPc {
    WI_INIT_ALL = 0,
    WI_CHECK    = 1,
    WI_BODY     = 2,
    WI_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_increase_count64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    uint64_t prev = 0;
    uint64_t cnt  = 0;
    int      pc   = WI_INIT_ALL;

    while (1) {
        if (pc == WI_INIT_ALL) {
            n    = (x & 3ull) + 1ull;
            s    = x;
            prev = x & 0xFFFFull;
            cnt  = 0ull;
            pc = WI_CHECK;
        } else if (pc == WI_CHECK) {
            pc = (n > 0ull) ? WI_BODY : WI_HALT;
        } else if (pc == WI_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w > prev) ? 1ull : 0ull);
            prev = w;
            s = s >> 16;
            n = n - 1ull;
            pc = WI_CHECK;
        } else if (pc == WI_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_increase_count64(0x4000300020001000)=%llu\n",
           (unsigned long long)vm_word_increase_count64_loop_target(0x4000300020001000ull));
    return 0;
}
