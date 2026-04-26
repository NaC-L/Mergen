/* PC-state VM that counts nonzero u16 words:
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w != 0) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_nonzero_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_nonzero_count64_loop (8-bit stride)
 *   - vm_word_ne_first_count64_loop (ne vs CAPTURED ref, not vs 0)
 *
 * Tests `icmp ne 0` predicate at u16 stride.  3 stateful slots
 * (n, s, cnt).
 */
#include <stdio.h>
#include <stdint.h>

enum WnVmPc {
    WN_INIT_ALL = 0,
    WN_CHECK    = 1,
    WN_BODY     = 2,
    WN_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_nonzero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WN_INIT_ALL;

    while (1) {
        if (pc == WN_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WN_CHECK;
        } else if (pc == WN_CHECK) {
            pc = (n > 0ull) ? WN_BODY : WN_HALT;
        } else if (pc == WN_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w != 0ull) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WN_CHECK;
        } else if (pc == WN_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_nonzero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_nonzero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
