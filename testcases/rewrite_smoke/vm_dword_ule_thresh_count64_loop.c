/* PC-state VM that counts u32 dwords with d <= 0x7FFFFFFF (low half):
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d <= 0x7FFFFFFF) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_ule_thresh_count64_loop_target.
 *
 * Tests `icmp ule` predicate at u32 stride.  Completes the ule
 * cmp-counter matrix (8/16/32 bit).
 */
#include <stdio.h>
#include <stdint.h>

enum DleVmPc {
    DLE_INIT_ALL = 0,
    DLE_CHECK    = 1,
    DLE_BODY     = 2,
    DLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_ule_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DLE_INIT_ALL;

    while (1) {
        if (pc == DLE_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DLE_CHECK;
        } else if (pc == DLE_CHECK) {
            pc = (n > 0ull) ? DLE_BODY : DLE_HALT;
        } else if (pc == DLE_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d <= 0x7FFFFFFFull) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DLE_CHECK;
        } else if (pc == DLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_ule_thresh_count64(1)=%llu\n",
           (unsigned long long)vm_dword_ule_thresh_count64_loop_target(1ull));
    return 0;
}
