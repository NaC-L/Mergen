/* PC-state VM that counts bytes strictly less than 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b < 0x80) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_lt_thresh_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (icmp eq, dynamic threshold)
 *   - vm_branchy_loop (conditional add with no threshold)
 *   - vm_bytematch64_loop (icmp eq against constant)
 *
 * Tests `icmp ult` + zext-i1 + add chain at byte stride.  Constant
 * threshold (0x80) splits bytes into 0..127 (counted) vs 128..255
 * (skipped).  3 stateful slots (n, s, cnt).
 */
#include <stdio.h>
#include <stdint.h>

enum BlVmPc {
    BL_INIT_ALL = 0,
    BL_CHECK    = 1,
    BL_BODY     = 2,
    BL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_lt_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BL_INIT_ALL;

    while (1) {
        if (pc == BL_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BL_CHECK;
        } else if (pc == BL_CHECK) {
            pc = (n > 0ull) ? BL_BODY : BL_HALT;
        } else if (pc == BL_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b < 0x80ull) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BL_CHECK;
        } else if (pc == BL_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_lt_thresh_count64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_lt_thresh_count64_loop_target(0xCAFEBABEull));
    return 0;
}
