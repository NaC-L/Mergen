/* PC-state VM that counts nonzero u32 dwords:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d != 0) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_nonzero_count64_loop_target.
 *
 * Distinct from:
 *   - vm_word_nonzero_count64_loop  (16-bit stride)
 *   - vm_dword_ne_first_count64_loop (ne vs CAPTURED ref, not vs 0)
 *
 * Tests `icmp ne 0` predicate at u32 stride.  Trip count is at most 2
 * (n_mask=1) so the lifter does not face a deep enumeration here.
 */
#include <stdio.h>
#include <stdint.h>

enum DnVmPc {
    DN_INIT_ALL = 0,
    DN_CHECK    = 1,
    DN_BODY     = 2,
    DN_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_nonzero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DN_INIT_ALL;

    while (1) {
        if (pc == DN_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DN_CHECK;
        } else if (pc == DN_CHECK) {
            pc = (n > 0ull) ? DN_BODY : DN_HALT;
        } else if (pc == DN_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d != 0ull) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DN_CHECK;
        } else if (pc == DN_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_nonzero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_nonzero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
