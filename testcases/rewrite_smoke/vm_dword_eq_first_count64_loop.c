/* PC-state VM that counts u32 dwords equal to the first dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; first = s & 0xFFFFFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d == first) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_eq_first_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (8-bit stride)
 *   - vm_word_eq_first_count64_loop (16-bit stride)
 *
 * Tests `icmp eq` cmp-counter at u32 stride.  Completes the
 * eq-first cmp-counter matrix (8/16/32 bit).  4 stateful slots
 * (n, s, first, cnt) within budget.
 */
#include <stdio.h>
#include <stdint.h>

enum DeVmPc {
    DE_INIT_ALL = 0,
    DE_CHECK    = 1,
    DE_BODY     = 2,
    DE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_eq_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = DE_INIT_ALL;

    while (1) {
        if (pc == DE_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            first = x & 0xFFFFFFFFull;
            cnt = 0ull;
            pc = DE_CHECK;
        } else if (pc == DE_CHECK) {
            pc = (n > 0ull) ? DE_BODY : DE_HALT;
        } else if (pc == DE_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d == first) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DE_CHECK;
        } else if (pc == DE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_eq_first_count64(0x100000001)=%llu\n",
           (unsigned long long)vm_dword_eq_first_count64_loop_target(0x0000000100000001ull));
    return 0;
}
