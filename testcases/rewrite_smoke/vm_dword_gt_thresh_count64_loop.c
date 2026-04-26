/* PC-state VM that counts u32 dwords strictly greater than 0x40000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d > 0x40000000) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_gt_thresh_count64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_lt_thresh_count64_loop (`<` complement at the same 0x40000000 cut)
 *   - vm_word_gt_thresh_count64_loop  (16-bit stride)
 *
 * Tests `icmp ugt` + zext + add chain at u32 stride.  3 stateful slots
 * (n, s, cnt).  Strict `>` predicate complements the existing dword lt
 * sample; dwords exactly equal to 0x40000000 are NOT counted.
 */
#include <stdio.h>
#include <stdint.h>

enum DgVmPc {
    DG_INIT_ALL = 0,
    DG_CHECK    = 1,
    DG_BODY     = 2,
    DG_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_gt_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DG_INIT_ALL;

    while (1) {
        if (pc == DG_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DG_CHECK;
        } else if (pc == DG_CHECK) {
            pc = (n > 0ull) ? DG_BODY : DG_HALT;
        } else if (pc == DG_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d > 0x40000000ull) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DG_CHECK;
        } else if (pc == DG_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_gt_thresh_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_gt_thresh_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
