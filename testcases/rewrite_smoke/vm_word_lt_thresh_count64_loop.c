/* PC-state VM that counts u16 words strictly less than 0x4000:
 *
 *   n = (x & 3) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     cnt = cnt + ((w < 0x4000) ? 1 : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_word_lt_thresh_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_lt_thresh_count64_loop (8-bit stride)
 *
 * Tests `icmp ult` + zext + add chain at u16 word stride.  3
 * stateful slots (n, s, cnt).
 */
#include <stdio.h>
#include <stdint.h>

enum WlVmPc {
    WL_INIT_ALL = 0,
    WL_CHECK    = 1,
    WL_BODY     = 2,
    WL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_lt_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = WL_INIT_ALL;

    while (1) {
        if (pc == WL_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = WL_CHECK;
        } else if (pc == WL_CHECK) {
            pc = (n > 0ull) ? WL_BODY : WL_HALT;
        } else if (pc == WL_BODY) {
            uint64_t w = s & 0xFFFFull;
            cnt = cnt + ((w < 0x4000ull) ? 1ull : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WL_CHECK;
        } else if (pc == WL_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_lt_thresh_count64(0x3000300030003000)=%llu\n",
           (unsigned long long)vm_word_lt_thresh_count64_loop_target(0x3000300030003000ull));
    return 0;
}
