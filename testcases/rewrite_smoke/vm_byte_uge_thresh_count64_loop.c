/* PC-state VM that counts bytes with high bit set:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b >= 0x80) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_uge_thresh_count64_loop_target.
 *
 * Tests `icmp uge` predicate at byte stride.  Adds `uge` to the
 * cmp-counter coverage matrix (which previously had eq/ne/ult/ugt/slt).
 */
#include <stdio.h>
#include <stdint.h>

enum BgVmPc {
    BG_INIT_ALL = 0,
    BG_CHECK    = 1,
    BG_BODY     = 2,
    BG_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_uge_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BG_INIT_ALL;

    while (1) {
        if (pc == BG_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BG_CHECK;
        } else if (pc == BG_CHECK) {
            pc = (n > 0ull) ? BG_BODY : BG_HALT;
        } else if (pc == BG_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b >= 0x80ull) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BG_CHECK;
        } else if (pc == BG_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_uge_thresh_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_uge_thresh_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
