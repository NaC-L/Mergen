/* PC-state VM that counts u32 dwords not equal to the first dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; first = s & 0xFFFFFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d != first) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_ne_first_count64_loop_target.
 *
 * Distinct from:
 *   - vm_word_ne_first_count64_loop  (16-bit stride)
 *   - vm_dword_eq_first_count64_loop (eq complement at the same stride)
 *
 * Tests `icmp ne` cmp-counter with captured-reference comparand at u32
 * stride.  4 stateful slots (n, s, first, cnt) within budget; trip count
 * is at most 2 so the lifter does not have to handle a deep enumeration.
 */
#include <stdio.h>
#include <stdint.h>

enum DneVmPc {
    DNE_INIT_ALL = 0,
    DNE_CHECK    = 1,
    DNE_BODY     = 2,
    DNE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_ne_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = DNE_INIT_ALL;

    while (1) {
        if (pc == DNE_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            first = x & 0xFFFFFFFFull;
            cnt = 0ull;
            pc = DNE_CHECK;
        } else if (pc == DNE_CHECK) {
            pc = (n > 0ull) ? DNE_BODY : DNE_HALT;
        } else if (pc == DNE_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d != first) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DNE_CHECK;
        } else if (pc == DNE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_ne_first_count64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_dword_ne_first_count64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
