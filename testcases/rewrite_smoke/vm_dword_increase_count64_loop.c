/* PC-state VM: count of u32 dwords strictly > previous dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; prev = s & 0xFFFFFFFF; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d > prev) ? 1 : 0);
 *     prev = d;
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_increase_count64_loop_target.
 *
 * Distinct from:
 *   - vm_word_increase_count64_loop  (16-bit stride)
 *   - vm_dword_eq_first_count64_loop (compares against fixed first)
 *
 * Tests CROSS-ITER u32 dword comparison: each iter compares current
 * dword to the dword from previous iter (stored in `prev` slot).
 * Trip count is at most 2 (n_mask=1) so the second iter is the only
 * one that can produce a positive count.
 */
#include <stdio.h>
#include <stdint.h>

enum DiVmPc {
    DI_INIT_ALL = 0,
    DI_CHECK    = 1,
    DI_BODY     = 2,
    DI_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_increase_count64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    uint64_t prev = 0;
    uint64_t cnt  = 0;
    int      pc   = DI_INIT_ALL;

    while (1) {
        if (pc == DI_INIT_ALL) {
            n    = (x & 1ull) + 1ull;
            s    = x;
            prev = x & 0xFFFFFFFFull;
            cnt  = 0ull;
            pc = DI_CHECK;
        } else if (pc == DI_CHECK) {
            pc = (n > 0ull) ? DI_BODY : DI_HALT;
        } else if (pc == DI_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d > prev) ? 1ull : 0ull);
            prev = d;
            s = s >> 32;
            n = n - 1ull;
            pc = DI_CHECK;
        } else if (pc == DI_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_increase_count64(0x4000000020000001)=%llu\n",
           (unsigned long long)vm_dword_increase_count64_loop_target(0x4000000020000001ull));
    return 0;
}
