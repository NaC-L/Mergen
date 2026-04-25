/* PC-state VM that counts bytes strictly greater than 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b > 0x80) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_gt_thresh_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_lt_thresh_count64_loop (`<` complement)
 *   - vm_byte_eq_first_count64_loop  (`==` dynamic)
 *
 * Tests `icmp ugt` + zext + add chain.  Strict `>` predicate
 * complements the `<` predicate from the lt-thresh sample.  Bytes
 * exactly equal to 0x80 are NOT counted.
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
uint64_t vm_byte_gt_thresh_count64_loop_target(uint64_t x) {
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
            cnt = cnt + ((b > 0x80ull) ? 1ull : 0ull);
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
    printf("vm_byte_gt_thresh_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_gt_thresh_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
